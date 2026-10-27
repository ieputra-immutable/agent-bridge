#!/usr/bin/env python3
"""Milestone 4 NAT matrix using disposable Linux user/network namespaces.

No host networking or installed bridge state is changed. Each scenario creates
separate endpoint, NAT-router and relay namespaces; owners are simulated only for
new test brokers. Requires iproute2, nftables and unprivileged user/network namespaces.
Evidence is local virtual-network acceptance, not physical WAN acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

PUBLIC = "198.18.0"
RELAY_IP = f"{PUBLIC}.10"
RELAY_PORT = 45000
SCENARIOS = ("direct", "restricted", "rebind")


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, text=True, capture_output=True, **kwargs)


def wait(label, inspect, seconds=50):
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
    parser.add_argument("--scenario", choices=("all", *SCENARIOS), default="all")
    parser.add_argument("--topology-only", action="store_true", help="Smoke-test isolated NAT setup without starting product processes")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--host-netns", help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if not args.inside:
        for executable in ("unshare", "nsenter", "ip", "nft"):
            if not shutil.which(executable):
                parser.error(f"Required executable missing: {executable}")
        output = (args.output or Path(tempfile.mkdtemp(prefix="ab-nat-matrix-", dir="/tmp"))).resolve()
        output.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(output, 0o700)
        scenarios = SCENARIOS if args.scenario == "all" else (args.scenario,)
        results = []
        for scenario in scenarios:
            folder = output / scenario
            folder.mkdir(mode=0o700)
            command = ["unshare", "--user", "--map-root-user", "--net", sys.executable,
                       str(Path(__file__).resolve()), "--inside", "--binary", str(binary),
                       "--output", str(folder), "--scenario", scenario,
                       "--host-netns", os.readlink("/proc/self/ns/net")]
            if args.topology_only:
                command.append("--topology-only")
            result = subprocess.run(command)
            results.append({"scenario": scenario, "exit_code": result.returncode})
            if result.returncode:
                break
        (output / "matrix.json").write_text(json.dumps({"scope": "isolated virtual NAT networks",
                                                       "scenarios": results,
                                                       "complete": len(results) == len(scenarios) and all(r["exit_code"] == 0 for r in results)}, indent=2) + "\n")
        print(f"Evidence: {output}", flush=True)
        return 0 if all(result["exit_code"] == 0 for result in results) else 1

    uid_map = Path("/proc/self/uid_map").read_text().split()
    if (os.geteuid() != 0 or len(uid_map) != 3 or uid_map[0] != "0" or uid_map[2] != "1"
            or not args.host_netns or os.readlink("/proc/self/ns/net") == args.host_netns):
        raise RuntimeError("Refusing network changes outside a new root-mapped user/network namespace")
    if args.scenario == "all":
        raise RuntimeError("Each scenario requires its own isolated namespace")

    output = args.output
    processes, files = [], []
    evidence = {"scenario": args.scenario, "scope": "local Linux virtual NAT networks; not physical WAN",
                "host_network_changed": False, "topology_only": args.topology_only, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "checks": []}

    def save(name, value):
        (output / name).write_text(json.dumps(value, indent=2) + "\n")

    def check(name, details=None):
        evidence["checks"].append({"check": name, "passed": True, "details": details})
        save("results.json", evidence)
        print(f"PASS [{args.scenario}]: {name}", flush=True)

    def spawn(argv, name):
        log = open(output / f"{name}.stdout.log", "w")
        err = open(output / f"{name}.stderr.log", "w")
        files.extend((log, err))
        process = subprocess.Popen(argv, stdout=log, stderr=err, text=True)
        processes.append(process)
        return process

    def ns(pid, argv, **kwargs):
        return run(["nsenter", "--target", str(pid), "--net", "--", *argv], **kwargs)

    def flush_conntrack(pid):
        # Equivalent to conntrack -F, only inside a known disposable router netns.
        source = """import socket,struct
s=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);s.bind((0,0));s.settimeout(2)
payload=struct.pack('BBH',socket.AF_INET,0,0)
s.send(struct.pack('IHHII',16+len(payload),(1<<8)|2,1|4,1,0)+payload)
r=s.recv(4096)
assert struct.unpack_from('H',r,4)[0]==2
assert struct.unpack_from('i',r,16)[0]==0, r
"""
        ns(pid, [sys.executable, "-c", source])

    try:
        run(["ip", "link", "set", "lo", "up"])
        run(["ip", "link", "add", "public", "type", "bridge"])
        run(["ip", "addr", "add", f"{PUBLIC}.1/24", "dev", "public"])
        run(["ip", "link", "set", "public", "up"])
        namespaces = {}
        for name in ("a", "b", "ra", "rb", "relay"):
            keeper = spawn(["unshare", "--net", "sleep", "900"], f"namespace-{name}")
            wait(f"namespace {name}", lambda p=keeper:
                 p.poll() is None and os.readlink(f"/proc/{p.pid}/ns/net") != os.readlink("/proc/self/ns/net"))
            namespaces[name] = keeper.pid
            ns(keeper.pid, ["ip", "link", "set", "lo", "up"])
        assert len({os.readlink(f"/proc/{pid}/ns/net") for pid in namespaces.values()}) == 5

        for name, suffix in (("ra", 2), ("rb", 3), ("relay", 10)):
            outside = f"h{name}"
            run(["ip", "link", "add", outside, "type", "veth", "peer", "name", "wan"])
            run(["ip", "link", "set", "wan", "netns", str(namespaces[name])])
            run(["ip", "link", "set", outside, "master", "public"])
            run(["ip", "link", "set", outside, "up"])
            ns(namespaces[name], ["ip", "addr", "add", f"{PUBLIC}.{suffix}/24", "dev", "wan"])
            ns(namespaces[name], ["ip", "link", "set", "wan", "up"])
            ns(namespaces[name], ["ip", "route", "add", "default", "via", f"{PUBLIC}.1"])
        for name, router, subnet in (("a", "ra", 1), ("b", "rb", 2)):
            run(["ip", "link", "add", "lan", "type", "veth", "peer", "name", "client"])
            run(["ip", "link", "set", "lan", "netns", str(namespaces[router])])
            run(["ip", "link", "set", "client", "netns", str(namespaces[name])])
            ns(namespaces[router], ["ip", "addr", "add", f"10.201.{subnet}.1/24", "dev", "lan"])
            ns(namespaces[router], ["ip", "link", "set", "lan", "up"])
            ns(namespaces[name], ["ip", "addr", "add", f"10.201.{subnet}.2/24", "dev", "client"])
            ns(namespaces[name], ["ip", "link", "set", "client", "up"])
            ns(namespaces[name], ["ip", "route", "add", "default", "via", f"10.201.{subnet}.1"])
            ns(namespaces[router], [sys.executable, "-c", "from pathlib import Path; Path('/proc/sys/net/ipv4/ip_forward').write_text('1\\n')"])

        public_a = f"{PUBLIC}.2"
        public_b = f"{PUBLIC}.3"

        def router_rules(router, public_ip, peer_ip, restrictive=False, relay_allowed=True):
            block = f"ip daddr {peer_ip} ip protocol udp counter drop\n  ip saddr {peer_ip} ip protocol udp counter drop" if restrictive else ""
            relay_block = "" if relay_allowed else f"ip daddr {RELAY_IP} ip protocol udp counter drop\n  ip saddr {RELAY_IP} ip protocol udp counter drop"
            rules = f"""flush ruleset
 table inet qa_filter {{
 chain input {{type filter hook input priority filter; policy drop; ct state established,related accept;}}
 chain forward {{
  type filter hook forward priority filter; policy drop;
  {block}
  {relay_block}
  ct state established,related counter accept
  iifname "lan" oifname "wan" ip daddr {RELAY_IP} udp dport {RELAY_PORT} counter accept
  iifname "lan" oifname "wan" ip daddr {peer_ip} ip protocol udp counter accept
  counter drop
 }}
 }}
 table ip qa_nat {{
 chain postrouting {{type nat hook postrouting priority srcnat; policy accept;
  oifname "wan" ip saddr 10.201.0.0/16 counter snat to {public_ip}
 }}
 }}
"""
            (output / f"{router}-firewall.nft").write_text(rules)
            ns(namespaces[router], ["nft", "-f", "-"], input=rules)

        restrictive = args.scenario == "restricted"
        router_rules("ra", public_a, public_b, restrictive)
        router_rules("rb", public_b, public_a, restrictive)
        check("five isolated namespaces; two independent outbound-only UDP NAT routers",
              {"public_a": public_a, "public_b": public_b, "relay": RELAY_IP,
               "direct_firewall_blocked": restrictive})

        # Verify this is dynamic hole punching, not accidental static forwarding:
        # both probes first learn their public tuple through the relay, then send
        # simultaneously to the other tuple from the same UDP socket.
        relay_probe_source = r"""import json,socket,sys
from pathlib import Path
out=Path(sys.argv[1]);s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('0.0.0.0',45000));s.settimeout(4);(out/'udp-probe-relay-ready').write_text('ready')
for _ in range(2):
 data,addr=s.recvfrom(128);s.sendto(json.dumps(addr).encode(),addr)
"""
        relay_probe = spawn(["nsenter", "-t", str(namespaces["relay"]), "-n", "--",
                             sys.executable, "-c", relay_probe_source, str(output)], "udp-probe-relay")
        wait("UDP relay probe ready", lambda: (output / "udp-probe-relay-ready").exists(), 5)
        endpoint_probe_source = r"""import json,socket,sys,time
from pathlib import Path
out=Path(sys.argv[1]);name=sys.argv[2];other=sys.argv[3];relay=sys.argv[4]
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',0));local=s.getsockname()[1]
s.settimeout(4);s.sendto(b'observe',(relay,45000));public=json.loads(s.recvfrom(256)[0])
tmp=out/(name+'-udp-probe-public.tmp');tmp.write_text(json.dumps({'public':public,'local_port':local}));tmp.replace(out/(name+'-udp-probe-public.json'))
until=time.monotonic()+5
while not (out/(other+'-udp-probe-public.json')).exists():
 assert time.monotonic()<until;time.sleep(.02)
peer=json.loads((out/(other+'-udp-probe-public.json')).read_text())['public']
s.settimeout(.08);received=False
for _ in range(25):
 s.sendto(b'hole-punch-probe',tuple(peer))
 try:
  data,addr=s.recvfrom(256)
  if data==b'hole-punch-probe' and list(addr)==peer:received=True
 except socket.timeout:pass
(out/(name+'-udp-probe-result.json')).write_text(json.dumps({'received':received,'public':public,'local_port':local}))
"""
        endpoint_probes = []
        for name, other in (("a", "b"), ("b", "a")):
            endpoint_probes.append(spawn(["nsenter", "-t", str(namespaces[name]), "-n", "--",
                                          sys.executable, "-c", endpoint_probe_source,
                                          str(output), name, other, RELAY_IP], f"udp-probe-{name}"))
        assert relay_probe.wait(timeout=6) == 0
        for probe in endpoint_probes:
            assert probe.wait(timeout=8) == 0
        probes = {name: json.loads((output / f"{name}-udp-probe-result.json").read_text()) for name in ("a", "b")}
        for name, expected in (("a", public_a), ("b", public_b)):
            assert probes[name]["public"] == [expected, probes[name]["local_port"]], probes
            assert probes[name]["received"] is not restrictive, probes
        check("dynamic port-preserving NAT permits coordinated UDP" if not restrictive else "restrictive firewall blocks coordinated direct UDP", probes)

        # No probe-created mapping may help the product's later hole punching.
        flush_conntrack(namespaces["ra"])
        flush_conntrack(namespaces["rb"])
        if args.topology_only:
            evidence["complete"] = True
            save("results.json", evidence)
            return 0

        states = {name: output / name for name in ("a", "b", "relay")}
        for state in states.values():
            state.mkdir(mode=0o700)
        relay_address = f"/ip4/{RELAY_IP}/udp/{RELAY_PORT}/quic-v1"
        relay = spawn(["nsenter", "-t", str(namespaces["relay"]), "-n", "--", str(binary),
                       "--state-dir", str(states["relay"]), "relay", "serve", "--listen",
                       f"/ip4/0.0.0.0/udp/{RELAY_PORT}/quic-v1", "--advertise", relay_address], "relay")

        def relay_identity():
            assert relay.poll() is None, "Relay exited"
            match = re.search(r'"peer_id"\s*:\s*"([^"]+)"', (output / "relay.stdout.log").read_text())
            return match.group(1) if match else None

        relay_id = wait("relay identity", relay_identity)
        configured = f"{relay_address}/p2p/{relay_id}"
        brokers = {}
        for name in ("a", "b"):
            brokers[name] = spawn(["nsenter", "-t", str(namespaces[name]), "-n", "--", str(binary),
                                   "--state-dir", str(states[name]), "serve", "--no-discovery",
                                   "--codex-bin", "/missing/codex"], f"broker-{name}")

        def cli(name, *arguments):
            return json.loads(ns(namespaces[name], [str(binary), "--state-dir", str(states[name]), *arguments]).stdout)

        def status(name):
            return cli(name, "status")["network"]

        def snapshot(label):
            for name in ("a", "b"):
                save(f"{name}-{label}.json", status(name))
            for router in ("ra", "rb"):
                (output / f"{router}-{label}-firewall.json").write_text(ns(namespaces[router], ["nft", "-j", "list", "ruleset"]).stdout)

        ids = {}
        for name in ("a", "b"):
            ids[name] = wait(f"broker {name}", lambda n=name: cli(n, "identity", "show"))["peer_id"]
            cli(name, "network", "relays", "add", configured)
            cli(name, "network", "enable", "--listen", "/ip4/0.0.0.0/udp/0/quic-v1")
        for name, other in (("a", "b"), ("b", "a")):
            wait(f"public discovery at {name}", lambda n=name, o=other: ids[o] in json.dumps(status(n).get("rendezvous", [])))
            assert cli(name, "peers", "list") == []
        snapshot("untrusted-discovery")
        check("outbound relay reservations and discovery grant no trust")

        cli("b", "pairing", "open", "--seconds", "120")
        transaction = cli("a", "pairing", "connect", ids["b"])["id"]

        def view(name, state):
            return next((v for v in cli(name, "pairing", "list")["requests"]
                         if v["id"] == transaction and v["state"] == state), None)

        wait("B pending pairing", lambda: view("b", "awaiting_accept"))
        cli("b", "pairing", "accept", transaction)
        av = wait("A code", lambda: view("a", "compare_code"))
        bv = wait("B code", lambda: view("b", "compare_code"))
        assert av["verification_code"] == bv["verification_code"]
        assert cli("a", "peers", "list") == cli("b", "peers", "list") == []
        # Simulated owners authorize only freshly created, disposable test brokers.
        for name, value in (("a", av), ("b", bv)):
            cli(name, "pairing", "confirm", transaction, "--code", value["verification_code"])
        wait("A paired", lambda: view("a", "paired"))
        wait("B paired", lambda: view("b", "paired"))
        for name in ("a", "b"):
            assert cli(name, "peers", "list")[0]["grants"] == []
        check("both simulated owners verify SAS; pairing grants no session access")

        def path(name):
            other = ids["b" if name == "a" else "a"]
            rows = status(name).get("paths", [])
            return next((row for row in rows if row.get("peer_id") == other), None)

        if restrictive:
            wait("relayed path at A", lambda: (row := path("a")) and row.get("path") == "relayed")
            wait("relayed path at B", lambda: (row := path("b")) and row.get("path") == "relayed")
            def failed_hole_punch_with_relay():
                failures, relayed = [], []
                for name, other in (("a", "b"), ("b", "a")):
                    network = status(name)
                    current = next((row for row in network.get("paths", []) if row.get("peer_id") == ids[other]), None)
                    assert current is None or current.get("path") != "direct", current
                    relayed.append(current is not None and current.get("path") == "relayed")
                    failures.extend({"endpoint": name, **row} for row in network.get("nat", {}).get("hole_punch", [])
                                    if row.get("peer_id") == ids[other] and row.get("state") == "failed" and row.get("attempts", 0) > 0)
                return failures if failures and all(relayed) else None

            failures = wait("actual failed hole punch with relay fallback", failed_hole_punch_with_relay, 40)
            save("failed-hole-punch.json", failures)
            check("restrictive NAT fails an actual hole punch and retains encrypted relay fallback", failures)
        else:
            wait("direct hole-punched path at A", lambda: (row := path("a")) and row.get("path") == "direct", 60)
            wait("direct hole-punched path at B", lambda: (row := path("b")) and row.get("path") == "direct", 60)
            check("coordinated hole punching upgrades both endpoints to direct")
        snapshot("paired-path")

        cli("b", "register", "inbox", "private", "--session", "private-nat-matrix")
        for name, other in (("a", "b"), ("b", "a")):
            cli(name, "peers", "share", ids[other], "--agent", "user")
        for name in ("a", "b"):
            wait(f"shared directory at {name}", lambda n=name: cli(n, "list", "--remote"))
            rows = cli(name, "list", "--remote")
            assert len(rows) == 1 and rows[0]["name"] == "user", rows
        initial_peers = {name: cli(name, "peers", "list") for name in ("a", "b")}

        def received(name, body):
            return next((row for row in cli(name, "history", "--limit", "100") if row["body"] == body), None)

        def acknowledge(name, message):
            wait(f"native inbox submission {name}", lambda: cli(name, "get", message["id"])["state"] in ("submitted", "acknowledged"))
            cli(name, "ack", "--agent", "user", message["id"])

        def exchange(body):
            original = cli("a", "send", "--from", "user", "--to", f'{ids["b"]}/user', "--message", body)
            incoming = wait("message delivery", lambda: received("b", body))
            acknowledge("b", incoming)
            wait("ack propagation", lambda: cli("a", "get", original["id"])["state"] == "acknowledged")
            reply = cli("b", "send", "--from", "user", "--to", f'{ids["a"]}/user', "--in-reply-to", incoming["id"], "--message", body + "_REPLY")
            got_reply = wait("correlated reply", lambda: received("a", body + "_REPLY"))
            assert got_reply["parent"] == original["id"]
            acknowledge("a", got_reply)
            wait("reply ACK propagation", lambda: cli("b", "get", reply["id"])["state"] == "acknowledged")
            assert len([m for m in cli("b", "history", "--limit", "100") if m["body"] == body]) == 1
            return original

        if args.scenario == "direct":
            # A confirmed direct path must carry application traffic without relay.
            router_rules("ra", public_a, public_b, relay_allowed=False)
            router_rules("rb", public_b, public_a, relay_allowed=False)
            blocked_at = time.monotonic()

            def discovery_expired_while_direct_survives():
                snapshots = {name: status(name) for name in ("a", "b")}
                return (time.monotonic() - blocked_at >= 35
                        and all(not network.get("rendezvous", []) for network in snapshots.values()))

            wait("rendezvous cache expires with relay UDP blocked", discovery_expired_while_direct_survives, 45)
            assert path("a")["path"] == path("b")["path"] == "direct"
            snapshot("relay-blocked-discovery-expired")
            exchange("DIRECT_WITH_RELAY_BLOCKED")
            assert path("a")["path"] == path("b")["path"] == "direct"
            check("message, ACK and correlated reply survive expired discovery with relay UDP blocked",
                  {"seconds_without_relay": round(time.monotonic() - blocked_at, 2)})
        else:
            exchange("INITIAL_PATH_EXCHANGE")
            check("message, ACK and correlated reply preserve private-session isolation")

        if args.scenario == "rebind":
            # Break an established direct path without touching identities or
            # application state. The broker must retry through its retained relay.
            router_rules("ra", public_a, public_b, restrictive=True)
            router_rules("rb", public_b, public_a, restrictive=True)
            exchange("RELAY_AFTER_DIRECT_BLOCK")
            wait("relay fallback after blocked direct path", lambda: (row := path("a")) and row.get("path") == "relayed", 90)
            wait("reverse relay fallback after blocked direct path", lambda: (row := path("b")) and row.get("path") == "relayed", 90)
            snapshot("direct-blocked-fallback")
            check("blocking an established direct path preserves delivery through relay fallback")
            router_rules("ra", public_a, public_b)
            router_rules("rb", public_b, public_a)
            wait("direct retry after firewall opens", lambda: (row := path("a")) and row.get("path") == "direct", 90)
            wait("reverse direct retry after firewall opens", lambda: (row := path("b")) and row.get("path") == "direct", 90)
            snapshot("direct-recovered")
            check("direct connectivity upgrades again after firewall reopens")
            cli("b", "network", "disable")
            queued = cli("a", "send", "--from", "user", "--to", f'{ids["b"]}/user', "--message", "QUEUED_DURING_REBIND")
            assert received("b", "QUEUED_DURING_REBIND") is None
            ns(namespaces["ra"], ["ip", "addr", "del", f"{public_a}/24", "dev", "wan"])
            public_a = f"{PUBLIC}.4"
            ns(namespaces["ra"], ["ip", "addr", "add", f"{public_a}/24", "dev", "wan"])
            router_rules("ra", public_a, public_b)
            router_rules("rb", public_b, public_a)
            flush_conntrack(namespaces["ra"])
            cli("b", "network", "enable", "--listen", "/ip4/0.0.0.0/udp/46103/quic-v1")
            incoming = wait("queued delivery after NAT and listener changes", lambda: received("b", "QUEUED_DURING_REBIND"), 90)
            acknowledge("b", incoming)
            wait("rebound queued ACK", lambda: cli("a", "get", queued["id"])["state"] == "acknowledged")
            assert len([m for m in cli("b", "history", "--limit", "100") if m["body"] == "QUEUED_DURING_REBIND"]) == 1
            for name in ("a", "b"):
                assert cli(name, "identity", "show")["peer_id"] == ids[name]
                # Authenticated display metadata can arrive asynchronously; pin
                # security-relevant identity, aliases, revocation and grants.
                current = cli(name, "peers", "list")
                policy_fields = ("peer_id", "alias", "revoked", "grants")
                assert [{key: row.get(key) for key in policy_fields} for row in current] == [
                    {key: row.get(key) for key in policy_fields} for row in initial_peers[name]]
            exchange("AFTER_NAT_REBIND")
            check("public NAT address/listener change preserves pinned durable delivery and grants")
            wait("direct upgrade after network changes", lambda: (row := path("a")) and row.get("path") == "direct", 90)
            wait("reverse direct upgrade after network changes", lambda: (row := path("b")) and row.get("path") == "direct", 90)
            check("direct connectivity recovers automatically after network changes")

        cli("b", "peers", "revoke", ids["a"])
        assert cli("b", "peers", "list")[0]["revoked"]
        try:
            denied = cli("a", "send", "--from", "user", "--to", f'{ids["b"]}/user', "--message", "MUST_NOT_ARRIVE_AFTER_REVOKE")
        except subprocess.CalledProcessError:
            denied = None
        wait("revoked peer disconnect", lambda: ids["b"] not in status("a").get("connected", []))
        assert received("b", "MUST_NOT_ARRIVE_AFTER_REVOKE") is None
        if denied is not None:
            assert cli("a", "get", denied["id"])["state"] != "acknowledged"
        check("revocation blocks direct or relayed application access")
        snapshot("final")
        evidence.update({"complete": True, "relay_peer_id": relay_id, "endpoint_peer_ids": ids})
        save("results.json", evidence)
        return 0
    except BaseException as error:
        if isinstance(error, subprocess.CalledProcessError):
            evidence["command_stderr"] = error.stderr
            print(error.stderr, file=sys.stderr, flush=True)
        evidence.update({"complete": False, "error": f"{type(error).__name__}: {error}"})
        save("results.json", evidence)
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
        for handle in files:
            handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
