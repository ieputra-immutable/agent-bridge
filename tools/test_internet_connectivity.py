#!/usr/bin/env python3
"""M5 disposable TCP-only / DNS-change acceptance; no host networking changes.

Each scenario enters new user, network AND mount namespaces. It creates separate
endpoint/relay network namespaces with outbound-only SNAT. 'blocked-udp' drops all
application and DNS UDP. 'dns-change' permits only UDP/53 to an isolated DNS fixture;
all application UDP stays blocked. DNS resolv.conf is bind-mounted ONLY in the new
mount namespace. Native owner approval is simulated only for disposable brokers.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import time

RELAY_IP = "10.203.3.2"
NEW_RELAY_IP = "10.203.3.3"
DNS_IP = "10.203.3.53"
QUIC_PORT = 45001
TCP_PORT = 45002
BACKUP_PORT = 45003
SCENARIOS = ("blocked-udp", "dns-change")


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, text=True, capture_output=True, **kwargs)


def wait(label, inspect, seconds=55):
    until = time.monotonic() + seconds
    last = None
    while time.monotonic() < until:
        try:
            value = inspect()
            if value:
                return value
        except (subprocess.SubprocessError, ValueError, KeyError, OSError) as error:
            last = str(error)
        time.sleep(.1)
    raise AssertionError(f"Timed out: {label}; last error: {last}")


def dns_fixture(mapping, ready):
    """Tiny bounded DNS fixture: relay.test A, no recursion/forwarding."""
    def answer(data):
        if len(data) < 12 or len(data) > 4096 or struct.unpack_from("!H", data, 4)[0] != 1:
            return b""
        offset, labels = 12, []
        while offset < len(data):
            length = data[offset]
            offset += 1
            if length == 0:
                break
            if length > 63 or offset + length > len(data):
                return b""
            labels.append(data[offset:offset + length].decode("ascii", "strict"))
            offset += length
        if offset + 4 > len(data):
            return b""
        kind, klass = struct.unpack_from("!HH", data, offset)
        question = data[12:offset + 4]
        name = ".".join(labels).lower()
        exists = name == "relay.test" and klass == 1
        count = int(exists and kind == 1)
        flags = 0x8180 if exists else 0x8183
        result = data[:2] + struct.pack("!HHHHH", flags, 1, count, 0, 0) + question
        if count:
            address = ipaddress.IPv4Address(mapping.read_text().strip()).packed
            result += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) + address
        return result

    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                response = answer(self.request[0])
                if response:
                    self.request[1].sendto(response, self.client_address)
            except (UnicodeError, ValueError, OSError):
                pass

    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            try:
                header = self.request.recv(2)
                if len(header) != 2:
                    return
                length = struct.unpack("!H", header)[0]
                if length > 4096:
                    return
                data = b""
                while len(data) < length:
                    block = self.request.recv(length - len(data))
                    if not block:
                        return
                    data += block
                response = answer(data)
                self.request.sendall(struct.pack("!H", len(response)) + response)
            except (UnicodeError, ValueError, OSError):
                pass

    import threading
    with socketserver.UDPServer((DNS_IP, 53), UDP) as udp, socketserver.TCPServer((DNS_IP, 53), TCP) as tcp:
        threading.Thread(target=tcp.serve_forever, daemon=True).start()
        ready.write_text("ready")
        udp.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--scenario", choices=("all", *SCENARIOS), default="all")
    parser.add_argument("--topology-only", action="store_true")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--host-netns", help=argparse.SUPPRESS)
    parser.add_argument("--host-mntns", help=argparse.SUPPRESS)
    parser.add_argument("--dns-fixture", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--dns-ready", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.dns_fixture:
        dns_fixture(args.dns_fixture, args.dns_ready)
        return 0
    if not args.binary:
        parser.error("--binary is required")
    binary = args.binary.resolve(strict=True)
    if not args.inside:
        for executable in ("unshare", "nsenter", "ip", "nft", "mount"):
            if not shutil.which(executable):
                parser.error(f"Missing executable: {executable}")
        output = (args.output or Path(tempfile.mkdtemp(prefix="ab-internet-qa-", dir="/tmp"))).resolve()
        output.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(output, 0o700)
        # Cargo may replace target/debug binaries during unrelated test builds.
        # Every role and recorded digest uses this immutable acceptance snapshot.
        frozen = output / "frozen-agent-bridge"
        shutil.copyfile(binary, frozen)
        frozen.chmod(0o700)
        binary = frozen
        results = []
        scenarios = SCENARIOS if args.scenario == "all" else (args.scenario,)
        for scenario in scenarios:
            folder = output / scenario
            folder.mkdir(mode=0o700)
            command = ["unshare", "--user", "--map-root-user", "--net", "--mount", sys.executable,
                       str(Path(__file__).resolve()), "--inside", "--binary", str(binary),
                       "--output", str(folder), "--scenario", scenario,
                       "--host-netns", os.readlink("/proc/self/ns/net"),
                       "--host-mntns", os.readlink("/proc/self/ns/mnt")]
            if args.topology_only:
                command.append("--topology-only")
            result = subprocess.run(command)
            results.append({"scenario": scenario, "exit_code": result.returncode})
            if result.returncode:
                break
        complete = len(results) == len(scenarios) and all(row["exit_code"] == 0 for row in results)
        (output / "matrix.json").write_text(json.dumps({"scope": "isolated virtual networks", "scenarios": results,
                                                       "complete": complete, "topology_only": args.topology_only}, indent=2) + "\n")
        print(f"Evidence: {output}", flush=True)
        return 0 if complete else 1

    uid_map = Path("/proc/self/uid_map").read_text().split()
    if (os.geteuid() != 0 or len(uid_map) != 3 or uid_map[0] != "0" or uid_map[2] != "1"
            or not args.host_netns or os.readlink("/proc/self/ns/net") == args.host_netns
            or not args.host_mntns or os.readlink("/proc/self/ns/mnt") == args.host_mntns
            or args.scenario == "all"):
        raise RuntimeError("Refusing changes outside new root-mapped user/network/mount namespaces")
    output, processes, files = args.output, [], []
    with open(binary, "rb") as executable:
        digest = hashlib.file_digest(executable, "sha256").hexdigest()
    evidence = {"scope": "Linux virtual TCP-only/DNS networks; not physical WAN", "scenario": args.scenario,
                "host_network_changed": False, "host_mounts_changed": False, "topology_only": args.topology_only,
                "binary_sha256": digest, "checks": []}

    def save(name, value):
        (output / name).write_text(json.dumps(value, indent=2) + "\n")

    def check(name, details=None):
        evidence["checks"].append({"check": name, "passed": True, "details": details})
        save("results.json", evidence)
        print(f"PASS [{args.scenario}]: {name}", flush=True)

    def spawn(argv, name):
        stdout = open(output / f"{name}.stdout.log", "w")
        stderr = open(output / f"{name}.stderr.log", "w")
        files.extend((stdout, stderr))
        child = subprocess.Popen(argv, stdout=stdout, stderr=stderr, text=True)
        processes.append(child)
        return child

    def ns(pid, argv, **kwargs):
        return run(["nsenter", "--target", str(pid), "--net", "--", *argv], **kwargs)

    def stop(child):
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=4)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()

    try:
        run(["mount", "--make-rprivate", "/"])
        run(["ip", "link", "set", "lo", "up"])
        namespaces = {}
        for name in ("a", "b", "relay"):
            keeper = spawn(["unshare", "--net", "sleep", "900"], f"namespace-{name}")
            wait(f"namespace {name}", lambda p=keeper: p.poll() is None and os.readlink(f"/proc/{p.pid}/ns/net") != os.readlink("/proc/self/ns/net"))
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
        ns(namespaces["relay"], ["ip", "addr", "add", f"{DNS_IP}/24", "dev", "cr"])
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
        dns = args.scenario == "dns-change"
        dns_rule = (f'iifname {{ "ga", "gb" }} oifname "gr" ip daddr {DNS_IP} udp dport 53 counter accept\n'
                    f'  iifname "gr" oifname {{ "ga", "gb" }} ip saddr {DNS_IP} udp sport 53 ct state established counter accept') if dns else ""
        rules = f"""table inet qa_tcp {{
 chain forward {{type filter hook forward priority filter; policy drop;
  iifname "ga" oifname "gb" counter drop
  iifname "gb" oifname "ga" counter drop
  {dns_rule}
  ip protocol udp counter drop
  ct state established,related counter accept
  iifname {{ "ga", "gb" }} oifname "gr" ip daddr {{ {RELAY_IP}, {NEW_RELAY_IP} }} tcp dport {{ {TCP_PORT}, {BACKUP_PORT} }} counter accept
  counter drop
 }}
}}
table ip qa_tcp_nat {{
 chain postrouting {{type nat hook postrouting priority srcnat; policy accept;
  oifname "gr" ip saddr {{ 10.203.1.0/24, 10.203.2.0/24 }} counter masquerade
 }}
}}
"""
        run(["nft", "-f", "-"], input=rules)
        (output / "firewall.nft").write_text(rules)
        check("isolated outbound-only SNAT; all application UDP and direct client traffic blocked",
              {"dns_udp_exception": dns})

        probe = spawn(["nsenter", "-t", str(namespaces["relay"]), "-n", "--", sys.executable, "-c",
                       "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',45009));s.settimeout(1);"
                       "\ntry:\n s.recvfrom(128);raise SystemExit(1)\nexcept socket.timeout:\n print('UDP blocked')"], "udp-probe")
        time.sleep(.1)
        ns(namespaces["a"], [sys.executable, "-c", f"import socket;socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b'blocked',('{RELAY_IP}',45009))"])
        assert probe.wait(timeout=4) == 0
        check("real endpoint-to-relay UDP probe is dropped")

        mapping = output / "dns-address.txt"
        mapping.write_text(RELAY_IP)
        if dns:
            resolv = output / "resolv.conf"
            resolv.write_text(f"nameserver {DNS_IP}\noptions timeout:1 attempts:1\n")
            run(["mount", "--bind", str(resolv), "/etc/resolv.conf"])
            # Host NSS may consult the host systemd-resolved socket before DNS.
            # Override only this disposable mount namespace, preserving all other databases.
            nsswitch = output / "nsswitch.conf"
            original_nss = Path("/etc/nsswitch.conf").read_text()
            nsswitch.write_text(re.sub(r"(?m)^hosts:.*$", "hosts: files dns", original_nss))
            run(["mount", "--bind", str(nsswitch), "/etc/nsswitch.conf"])
            fixture = spawn(["nsenter", "-t", str(namespaces["relay"]), "-n", "--", sys.executable,
                             str(Path(__file__).resolve()), "--dns-fixture", str(mapping), "--dns-ready", str(output / "dns.ready")], "dns")
            wait("DNS fixture", lambda: (output / "dns.ready").exists())
            answer = ns(namespaces["a"], [sys.executable, "-c", "import socket;print(socket.gethostbyname('relay.test'))"]).stdout.strip()
            assert answer == RELAY_IP, answer
            check("private mount namespace DNS fixture resolves relay.test")
        if args.topology_only:
            evidence["complete"] = True
            save("results.json", evidence)
            return 0

        states = {name: output / name for name in ("a", "b", "primary", "backup", "impostor")}
        for state in states.values():
            state.mkdir(mode=0o700)

        def start_relay(state, name, address, backup=False):
            tcp_port = BACKUP_PORT if backup else TCP_PORT
            if backup:
                options = ["--listen", f"/ip4/0.0.0.0/tcp/{tcp_port}", "--advertise", f"/ip4/{address}/tcp/{tcp_port}"]
            else:
                options = ["--listen", f"/ip4/0.0.0.0/udp/{QUIC_PORT}/quic-v1", "--advertise", f"/ip4/{address}/udp/{QUIC_PORT}/quic-v1",
                           "--tcp-listen", f"/ip4/0.0.0.0/tcp/{tcp_port}", "--tcp-advertise", f"/ip4/{address}/tcp/{tcp_port}"]
            child = spawn(["nsenter", "-t", str(namespaces["relay"]), "-n", "--", str(binary), "--state-dir", str(state), "relay", "serve", *options], name)
            def ready():
                assert child.poll() is None, f"Relay {name} exited"
                content = (output / f"{name}.stdout.log").read_text()
                rows = [json.loads(line) for line in content.splitlines() if line.strip().startswith("{")]
                return next((row for row in reversed(rows) if row.get("listening")), None)
            info = wait(f"relay {name}", ready)
            return child, info["peer_id"]

        primary, primary_id = start_relay(states["primary"], "primary", RELAY_IP)
        backup, backup_id = start_relay(states["backup"], "backup", RELAY_IP, backup=True)
        assert primary_id != backup_id
        for name in ("a", "b"):
            spawn(["nsenter", "-t", str(namespaces[name]), "-n", "--", str(binary), "--state-dir", str(states[name]),
                   "serve", "--no-discovery", "--codex-bin", "/missing/codex"], f"broker-{name}")

        def cli(name, *arguments):
            return json.loads(ns(namespaces[name], [str(binary), "--state-dir", str(states[name]), *arguments]).stdout)

        def fails(name, *arguments):
            try:
                cli(name, *arguments)
            except subprocess.CalledProcessError:
                return True
            return False

        ids = {name: wait(f"broker {name}", lambda n=name: cli(n, "identity", "show"))["peer_id"] for name in ("a", "b")}
        for name in ("a", "b"):
            cli(name, "network", "enable", "--listen", "/ip4/0.0.0.0/udp/0/quic-v1")
        wrong = f"/ip4/{RELAY_IP}/tcp/{BACKUP_PORT}/p2p/{primary_id}"
        cli("a", "network", "relays", "add", wrong)
        wait("wrong relay key rejected", lambda: any(row.get("state") == "error" and "peer" in str(row.get("last_error", "")).lower() for row in cli("a", "status")["network"].get("relays", [])))
        assert cli("a", "peers", "list") == []
        cli("a", "network", "relays", "remove", primary_id)
        assert cli("a", "network", "relays", "list") == []
        check("wrong pinned relay key is refused without granting endpoint trust")

        host = "/dns4/relay.test" if dns else f"/ip4/{RELAY_IP}"
        routes = [f"{host}/udp/{QUIC_PORT}/quic-v1/p2p/{primary_id}", f"{host}/tcp/{TCP_PORT}/p2p/{primary_id}"]
        if not dns:
            routes.append(f"/ip4/{RELAY_IP}/tcp/{BACKUP_PORT}/p2p/{backup_id}")
        for route in routes:
            cli("b", "network", "relays", "add", route)
        wait("B TCP reservation", lambda: any(row.get("state") == "reserved" and "/tcp/" in row.get("address", "") for row in cli("b", "status")["network"].get("relays", [])))
        invite = cli("b", "pairing", "invite", "--seconds", "600", "--svg", str(output / "invitation.svg"))
        link = invite["link"]
        assert link.startswith("agent-bridge://") and (output / "invitation.svg").is_file()
        import xml.etree.ElementTree as ET
        ET.parse(output / "invitation.svg")
        assert fails("a", "pairing", "connect", link)
        assert cli("a", "network", "relays", "list") == []
        changed = link[:-1] + ("A" if link[-1] != "A" else "B")
        assert fails("a", "pairing", "connect", changed, "--use-invite-relays")
        assert cli("a", "network", "relays", "list") == []
        check("signed link/QR generation; unfamiliar operators require explicit adoption; tampering changes nothing")
        transaction = cli("a", "pairing", "connect", link, "--use-invite-relays")["id"]

        def view(name, state):
            return next((row for row in cli(name, "pairing", "list")["requests"] if row["id"] == transaction and row["state"] == state), None)

        wait("pending link pairing", lambda: view("b", "awaiting_accept"))
        cli("b", "pairing", "accept", transaction)
        av = wait("A code", lambda: view("a", "compare_code"))
        bv = wait("B code", lambda: view("b", "compare_code"))
        assert av["verification_code"] == bv["verification_code"]
        assert cli("a", "peers", "list") == cli("b", "peers", "list") == []
        for name, value in (("a", av), ("b", bv)):
            cli(name, "pairing", "confirm", transaction, "--code", value["verification_code"])
        wait("A paired", lambda: view("a", "paired"))
        wait("B paired", lambda: view("b", "paired"))
        for name in ("a", "b"):
            assert cli(name, "peers", "list")[0]["grants"] == []
        check("link routes automatically carry SAS; both simulated owners required; no session grants")

        cli("b", "register", "inbox", "private", "--session", "private-internet-qa")
        for name, other in (("a", "b"), ("b", "a")):
            cli(name, "peers", "share", ids[other], "--agent", "user")
        for name in ("a", "b"):
            rows = wait(f"directory {name}", lambda n=name: cli(n, "list", "--remote"))
            assert len(rows) == 1 and rows[0]["name"] == "user", rows

        def received(name, body):
            return next((row for row in cli(name, "history", "--limit", "100") if row["body"] == body), None)

        def acknowledge(name, message):
            wait(f"inbox {name}", lambda: cli(name, "get", message["id"])["state"] in ("submitted", "acknowledged"))
            cli(name, "ack", "--agent", "user", message["id"])

        def exchange(body):
            sent = cli("a", "send", "--from", "user", "--to", f'{ids["b"]}/user', "--message", body)
            incoming = wait("TCP relay message", lambda: received("b", body))
            acknowledge("b", incoming)
            wait("message ACK", lambda: cli("a", "get", sent["id"])["state"] == "acknowledged")
            reply = cli("b", "send", "--from", "user", "--to", f'{ids["a"]}/user', "--in-reply-to", incoming["id"], "--message", body + "_REPLY")
            returned = wait("TCP relay reply", lambda: received("a", body + "_REPLY"))
            assert returned["parent"] == sent["id"]
            acknowledge("a", returned)
            wait("reply ACK", lambda: cli("b", "get", reply["id"])["state"] == "acknowledged")
            assert len([row for row in cli("b", "history", "--limit", "100") if row["body"] == body]) == 1
            return sent

        def paths_tcp():
            for name, other in (("a", "b"), ("b", "a")):
                network = cli(name, "status")["network"]
                assert any(row.get("state") == "reserved" and "/tcp/" in row.get("address", "") for row in network.get("relays", []))
                row = next(row for row in network.get("paths", []) if row["peer_id"] == ids[other])
                assert row["path"] == "relayed" and row["direct_connections"] == 0, row
        exchange("TCP_ONLY_LINK_HELLO")
        paths_tcp()
        check("TCP relay message/ACK/reply succeeds with UDP blocked; private session excluded")
        policies = {name: [{key: peer[key] for key in ("peer_id", "alias", "revoked", "grants")} for peer in cli(name, "peers", "list")] for name in ("a", "b")}

        cli("b", "network", "disable")
        queued = cli("a", "send", "--from", "user", "--to", f'{ids["b"]}/user', "--message", "QUEUED_INTERNET_RECOVERY")
        assert received("b", "QUEUED_INTERNET_RECOVERY") is None
        stop(primary)
        if dns:
            ns(namespaces["relay"], ["ip", "addr", "add", f"{NEW_RELAY_IP}/24", "dev", "cr"])
            ns(namespaces["relay"], ["ip", "addr", "del", f"{RELAY_IP}/24", "dev", "cr"])
            mapping.write_text(NEW_RELAY_IP)
            impostor, impostor_id = start_relay(states["impostor"], "impostor", NEW_RELAY_IP)
            assert impostor_id != primary_id
            changed_answer = ns(namespaces["a"], [sys.executable, "-c", "import socket;print(socket.gethostbyname('relay.test'))"]).stdout.strip()
            assert changed_answer == NEW_RELAY_IP, changed_answer
            wait("changed DNS refuses different operator key", lambda: any(
                row.get("state") == "error" and "/tcp/" in str(row.get("last_error", ""))
                and "unexpected peer" in str(row.get("last_error", "")).lower()
                for row in cli("a", "status")["network"].get("relays", [])), 70)
            assert received("b", "QUEUED_INTERNET_RECOVERY") is None
            check("DNS address change cannot substitute an operator key")
            stop(impostor)
            primary, same_id = start_relay(states["primary"], "primary-restarted", NEW_RELAY_IP)
            assert same_id == primary_id
        cli("b", "network", "enable", "--listen", "/ip4/0.0.0.0/udp/0/quic-v1")
        incoming = wait("queued delivery after relay loss/address change", lambda: received("b", "QUEUED_INTERNET_RECOVERY"), 90)
        acknowledge("b", incoming)
        wait("recovered ACK", lambda: cli("a", "get", queued["id"])["state"] == "acknowledged")
        assert len([row for row in cli("b", "history", "--limit", "100") if row["body"] == "QUEUED_INTERNET_RECOVERY"]) == 1
        for name in ("a", "b"):
            assert cli(name, "identity", "show")["peer_id"] == ids[name]
            assert [{key: peer[key] for key in ("peer_id", "alias", "revoked", "grants")} for peer in cli(name, "peers", "list")] == policies[name]
        paths_tcp()
        exchange("TCP_AFTER_RECOVERY")
        check("DNS/public-address restart recovers pinned queued delivery once" if dns else "independent operator failover recovers queued delivery once")

        cli("b", "peers", "revoke", ids["a"])
        try:
            denied = cli("a", "send", "--from", "user", "--to", f'{ids["b"]}/user', "--message", "DENIED_AFTER_REVOKE")
        except subprocess.CalledProcessError:
            denied = None
        wait("revoked endpoint disconnected", lambda: ids["b"] not in cli("a", "status")["network"].get("connected", []))
        assert received("b", "DENIED_AFTER_REVOKE") is None
        if denied:
            assert cli("a", "get", denied["id"])["state"] != "acknowledged"
        for name in ("a", "b"):
            save(f"{name}-final-status.json", cli(name, "status"))
        (output / "firewall-final.json").write_text(run(["nft", "-j", "list", "ruleset"]).stdout)
        check("revocation blocks TCP relayed access")
        evidence.update({"complete": True, "endpoint_peer_ids": ids, "primary_peer_id": primary_id, "backup_peer_id": backup_id})
        save("results.json", evidence)
        return 0
    except BaseException as error:
        evidence.update({"complete": False, "error": f"{type(error).__name__}: {error}"})
        if isinstance(error, subprocess.CalledProcessError):
            evidence["command_stderr"] = error.stderr
            print(error.stderr, file=sys.stderr, flush=True)
        save("results.json", evidence)
        raise
    finally:
        for child in reversed(processes):
            stop(child)
        for handle in files:
            handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
