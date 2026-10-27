#!/usr/bin/env python3
"""Isolated Linux NAT acceptance test; never changes the host network.

Run from the host as an ordinary user:
  python3 tools/test_relay_nat.py --binary /absolute/path/to/agent-bridge

Requires unprivileged user/network namespaces, iproute2, nsenter and nftables.
All routing/firewall changes happen inside a new user + network namespace.
Three nested network namespaces hold two brokers and a relay; the only permitted
forwarded traffic is client -> relay UDP, with SNAT and established return packets.
Human comparison/approval is simulated ONLY for these newly created test brokers.
The resulting evidence is a local network-namespace test, not physical WAN QA.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

RELAY_IP = "10.203.3.2"
RELAY_PORT = 45000


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, text=True, capture_output=True, **kwargs)


def wait(label, inspect, seconds=40):
    until = time.monotonic() + seconds
    last = None
    while time.monotonic() < until:
        try:
            value = inspect()
            if value:
                return value
        except (subprocess.SubprocessError, ValueError, KeyError, OSError) as error:
            last = str(error)
        time.sleep(0.1)
    raise AssertionError(f"Timed out: {label}; last error: {last}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--host-netns", help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if not args.inside:
        for tool in ("unshare", "nsenter", "ip", "nft"):
            if not shutil.which(tool):
                parser.error(f"Required executable missing: {tool}")
        output = args.output or Path(tempfile.mkdtemp(prefix="ab-nat-qa-", dir="/tmp"))
        output = output.resolve()
        output.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(output, 0o700)
        command = ["unshare", "--user", "--map-root-user", "--net", sys.executable,
                   str(Path(__file__).resolve()), "--inside", "--binary", str(binary),
                   "--output", str(output), "--host-netns", os.readlink("/proc/self/ns/net")]
        result = subprocess.run(command)
        print(f"Evidence: {output}")
        return result.returncode

    uid_map = Path("/proc/self/uid_map").read_text().split()
    if (os.geteuid() != 0 or len(uid_map) != 3 or uid_map[0] != "0" or uid_map[2] != "1"
            or not args.host_netns or os.readlink("/proc/self/ns/net") == args.host_netns):
        raise RuntimeError("Refusing networking changes outside isolated root-mapped namespace")
    output = args.output
    processes = []
    files = []
    evidence = {"scope": "local Linux user/network namespaces; not physical WAN",
                "host_network_changed": False, "checks": []}

    def check(name, details=None):
        evidence["checks"].append({"check": name, "passed": True, "details": details})
        (output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print(f"PASS: {name}", flush=True)

    def spawn(argv, name):
        log = open(output / f"{name}.stdout.log", "w")
        err = open(output / f"{name}.stderr.log", "w")
        files.extend((log, err))
        process = subprocess.Popen(argv, stdout=log, stderr=err, text=True)
        processes.append(process)
        return process

    def ns(pid, argv, **kwargs):
        return run(["nsenter", "--target", str(pid), "--net", "--", *argv], **kwargs)

    try:
        run(["ip", "link", "set", "lo", "up"])
        namespaces = {}
        for name in ("a", "b", "relay"):
            keeper = spawn(["unshare", "--net", "sleep", "900"], f"namespace-{name}")
            wait(f"network namespace {name}", lambda p=keeper:
                 p.poll() is None and os.readlink(f"/proc/{p.pid}/ns/net") != os.readlink("/proc/self/ns/net"))
            namespaces[name] = keeper.pid
        assert len({os.readlink(f"/proc/{pid}/ns/net") for pid in namespaces.values()}) == 3
        for name, subnet, gateway, device in (("a", 1, "ga", "ca"), ("b", 2, "gb", "cb"), ("relay", 3, "gr", "cr")):
            pid = namespaces[name]
            run(["ip", "link", "add", gateway, "type", "veth", "peer", "name", device])
            run(["ip", "link", "set", device, "netns", str(pid)])
            run(["ip", "addr", "add", f"10.203.{subnet}.1/24", "dev", gateway])
            run(["ip", "link", "set", gateway, "up"])
            ns(pid, ["ip", "link", "set", "lo", "up"])
            ns(pid, ["ip", "addr", "add", f"10.203.{subnet}.2/24", "dev", device])
            ns(pid, ["ip", "link", "set", device, "up"])
            ns(pid, ["ip", "route", "add", "default", "via", f"10.203.{subnet}.1"])
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
        rules = f"""table inet agent_bridge_qa {{
 chain forward {{
  type filter hook forward priority filter; policy drop;
  iifname "ga" oifname "gb" counter drop
  iifname "gb" oifname "ga" counter drop
  ct state established,related counter accept
  iifname {{ "ga", "gb" }} oifname "gr" ip daddr {RELAY_IP} udp dport {RELAY_PORT} counter accept
  counter drop
 }}
}}
table ip agent_bridge_qa_nat {{
 chain postrouting {{
  type nat hook postrouting priority srcnat; policy accept;
  oifname "gr" ip saddr {{ 10.203.1.0/24, 10.203.2.0/24 }} counter masquerade
 }}
}}
"""
        run(["nft", "-f", "-"], input=rules)
        (output / "firewall.nft").write_text(rules)
        check("isolated namespaces and outbound-only SNAT firewall created")

        # Confirm a client-to-client UDP packet cannot cross the forwarding filter.
        probe = spawn(["nsenter", "-t", str(namespaces["b"]), "-n", "--", sys.executable, "-c",
                       "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                       "s.bind(('0.0.0.0',46000)); s.settimeout(1.5); "
                       "\ntry:\n s.recvfrom(128); raise SystemExit(1)\nexcept socket.timeout:\n print('blocked')"], "direct-probe")
        time.sleep(0.1)
        ns(namespaces["a"], [sys.executable, "-c", "import socket; socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b'blocked-direct-probe',('10.203.2.2',46000))"])
        assert probe.wait(timeout=4) == 0, "Direct UDP route unexpectedly permitted"
        check("direct client-to-client UDP blocked")

        states = {name: output / name for name in ("a", "b", "relay")}
        for state in states.values():
            state.mkdir(mode=0o700)
        relay_addr = f"/ip4/{RELAY_IP}/udp/{RELAY_PORT}/quic-v1"
        relay = spawn(["nsenter", "-t", str(namespaces["relay"]), "-n", "--", str(binary),
                       "--state-dir", str(states["relay"]), "relay", "serve", "--listen",
                       f"/ip4/0.0.0.0/udp/{RELAY_PORT}/quic-v1", "--advertise", relay_addr], "relay")

        def relay_identity():
            assert relay.poll() is None, "Relay exited; inspect relay stderr"
            content = (output / "relay.stdout.log").read_text()
            match = re.search(r'"peer_id"\s*:\s*"([^"]+)"', content)
            return match.group(1) if match else None

        relay_id = wait("relay identity", relay_identity)
        configured = f"{relay_addr}/p2p/{relay_id}"
        brokers = {}
        for name in ("a", "b"):
            brokers[name] = spawn(["nsenter", "-t", str(namespaces[name]), "-n", "--", str(binary),
                                   "--state-dir", str(states[name]), "serve", "--no-discovery",
                                   "--codex-bin", "/missing/codex"], f"broker-{name}")

        def cli(name, *arguments):
            result = ns(namespaces[name], [str(binary), "--state-dir", str(states[name]), *arguments])
            return json.loads(result.stdout)

        ids = {}
        for name in ("a", "b"):
            ids[name] = wait(f"broker {name} identity", lambda n=name: cli(n, "identity", "show"))["peer_id"]
            cli(name, "network", "relays", "add", configured)
            cli(name, "network", "enable", "--listen", "/ip4/0.0.0.0/udp/0/quic-v1")
        assert ids["a"] != ids["b"] != relay_id
        wait("A discovers B through rendezvous", lambda: ids["b"] in json.dumps(cli("a", "status")["network"].get("rendezvous", [])))
        wait("B discovers A through rendezvous", lambda: ids["a"] in json.dumps(cli("b", "status")["network"].get("rendezvous", [])))
        for name in ("a", "b"):
            assert cli(name, "peers", "list") == []
            (output / f"{name}-discovery.json").write_text(json.dumps(cli(name, "status"), indent=2) + "\n")
        check("outbound relay reservations and rendezvous discover untrusted endpoints")

        cli("b", "pairing", "open", "--seconds", "120")
        pairing = cli("a", "pairing", "connect", ids["b"])
        transaction = pairing["id"]

        def view(name, state):
            rows = cli(name, "pairing", "list")["requests"]
            return next((row for row in rows if row["id"] == transaction and row["state"] == state), None)

        wait("pending request at B", lambda: view("b", "awaiting_accept"))
        cli("b", "pairing", "accept", transaction)
        av = wait("A comparison code", lambda: view("a", "compare_code"))
        bv = wait("B comparison code", lambda: view("b", "compare_code"))
        assert av["verification_code"] == bv["verification_code"]
        assert cli("a", "peers", "list") == cli("b", "peers", "list") == []
        # Simulated local owners approve only these disposable isolated test brokers.
        cli("a", "pairing", "confirm", transaction, "--code", av["verification_code"])
        cli("b", "pairing", "confirm", transaction, "--code", bv["verification_code"])
        wait("A paired", lambda: view("a", "paired"))
        wait("B paired", lambda: view("b", "paired"))
        assert cli("a", "peers", "list")[0]["grants"] == []
        assert cli("b", "peers", "list")[0]["grants"] == []
        check("SAS pairing over relay requires both simulated owner confirmations; no grants")

        cli("b", "register", "inbox", "private", "--session", "private-nat-qa")
        for name, peer in (("a", ids["b"]), ("b", ids["a"])):
            cli(name, "peers", "share", peer, "--agent", "user")
        for name in ("a", "b"):
            rows = wait(f"permitted directory at {name}", lambda n=name: cli(n, "list", "--remote"))
            assert len(rows) == 1 and rows[0]["name"] == "user", rows
        sent = cli("a", "send", "--from", "user", "--to", f'{ids["b"]}/user', "--message", "NAT_RELAY_HELLO")
        origin_id = sent["id"]

        def received(name, body):
            rows = cli(name, "history", "--limit", "100")
            return next((row for row in rows if row["body"] == body), None)

        incoming = wait("relay message arrives", lambda: received("b", "NAT_RELAY_HELLO"))
        wait("B inbox submission", lambda: cli("b", "get", incoming["id"])["state"] in ("sending", "submitted"))
        cli("b", "ack", "--agent", "user", incoming["id"])
        wait("acknowledgement propagates", lambda: cli("a", "get", origin_id)["state"] == "acknowledged")
        cli("b", "send", "--from", "user", "--to", f'{ids["a"]}/user', "--in-reply-to", incoming["id"], "--message", "NAT_RELAY_REPLY")
        reply = wait("correlated reply", lambda: received("a", "NAT_RELAY_REPLY"))
        assert reply["parent"] == origin_id
        wait("A inbox submission", lambda: cli("a", "get", reply["id"])["state"] in ("sending", "submitted"))
        cli("a", "ack", "--agent", "user", reply["id"])
        check("encrypted relayed message, acknowledgement and correlated reply; private session excluded")

        cli("b", "peers", "revoke", ids["a"])
        assert cli("b", "peers", "list")[0]["revoked"]
        try:
            denied = cli("a", "send", "--from", "user", "--to", f'{ids["b"]}/user', "--message", "MUST_NOT_ARRIVE_AFTER_REVOKE")
        except subprocess.CalledProcessError:
            # A freshly invalidated directory may reject locally before enqueue.
            denied = None
        wait("revoked endpoint disconnected", lambda: ids["b"] not in cli("a", "status")["network"].get("connected", []))
        if denied is not None:
            # A cannot distinguish remote revocation from an offline destination;
            # its durable transfer can remain queued instead of learning 'blocked'.
            record = cli("a", "get", denied["id"])
            assert record["state"] != "acknowledged"
            (output / "post-revoke-origin-transfer.json").write_text(json.dumps(record, indent=2) + "\n")
        assert received("b", "MUST_NOT_ARRIVE_AFTER_REVOKE") is None
        check("revocation disconnects endpoint and prevents further relayed delivery")
        for name in ("a", "b"):
            (output / f"{name}-final-status.json").write_text(json.dumps(cli(name, "status"), indent=2) + "\n")
        (output / "firewall-final.json").write_text(run(["nft", "-j", "list", "ruleset"]).stdout)
        evidence["relay_peer_id"] = relay_id
        evidence["endpoint_peer_ids"] = ids
        evidence["complete"] = True
        (output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
        return 0
    except BaseException as error:
        evidence["complete"] = False
        evidence["error"] = f"{type(error).__name__}: {error}"
        (output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
        raise
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for file in files:
            file.close()


if __name__ == "__main__":
    raise SystemExit(main())
