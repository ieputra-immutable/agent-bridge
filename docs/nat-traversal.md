# Automatic direct connections through NAT

Milestone 4 adds libp2p AutoNAT v2 reachability checks and DCUtR hole punching to
the existing [public rendezvous/relay setup](public-relays.md). No new account,
router forwarding rule or pairing authority is introduced. When a direct path
works, messages use authenticated encrypted QUIC; otherwise the existing encrypted
relay path remains available.

## Normal use

Configure one or more independent operators and enable networking as before:

```sh
agent-bridge network relays add /ip4/SERVER_IP/udp/4001/quic-v1/p2p/RELAY_PEER_ID
agent-bridge network enable --listen /ip4/0.0.0.0/udp/0/quic-v1
```

Use [owner-approved pairing](lan-pairing.md), compare the verification code through
a trusted channel, and explicitly [share the selected sessions](session-sharing.md).
Pairing requests stay on the restricted channel. A discovered or merely connected
machine cannot trigger hole punching: only paired endpoint identities may do so.

The bridge connects through a configured relay, exchanges current address
candidates and coordinates simultaneous direct UDP attempts using DCUtR. After a
new direct connection authenticates the same endpoint key, it retires redundant
endpoint relay circuits. Infrastructure connections and reservations are retained
for discovery, future contact and fallback. Direct success changes no identity,
trust record, session grant or queued message destination.

Relays must support the standard DCUtR stream forwarding, not terminate the
endpoint handshake. A milestone 3 node can still relay traffic; upgrading the node
to milestone 4 also enables its bounded AutoNAT v2 service. Lack of AutoNAT support
leaves reachability unknown and does not prevent ordinary relay communication.

No automatic UPnP, PCP or router configuration is performed. Direct traversal is
best effort. Symmetric mappings, restrictive filtering, carrier NAT or blocked UDP
may prevent it. A reachable relay remains necessary when a direct path fails.
[Milestone 5](internet-invitations.md) adds encrypted TCP relay fallback, DNS dialing
and signed connection links/QR codes.

## Inspect the active path

```sh
agent-bridge status
agent-bridge peers connections
```

The network status contains:

- `paths`: authenticated endpoint peer IDs, `direct` or `relayed`, live connection
  counts and observed transport addresses. A direct connection takes precedence.
- `nat.reachability`: `public`, `private` or `unknown` from recent AutoNAT v2
  outcomes. This is a diagnostic observation, never a permission or trust decision.
- `nat.observed_addresses`: bounded own-address observations, the configured
  observer's peer ID, whether a recent dialback verified reachability, and expiry.
- `nat.hole_punch`: bounded per-peer outcomes, counters and last error.

`peers connections` includes `path` and `transport` only as live authenticated
information for connected trusted peers; disabled, offline, revoked and unpaired
rows have null path information. Infrastructure connections do not masquerade as
trusted agent connections. A transport connection still does not establish agent
receipt, native execution or task completion.

`public` means a recent nonce-verified dialback reached the tested address from a
configured helper. It does not prove all internet paths are reachable. `private`
means a recent attempted callback failed; stale mappings or restrictive policy may
also cause failure. Missing/expired results, unsupported protocols and ordinary
probe rate rejection leave `unknown`. A private result does not prevent coordinated
hole punching, and an unknown result does not prevent relay messaging.

## Recovery and delivery

Configured infrastructure supplies authenticated observations of the bridge's own
QUIC mapping. Identify requests refresh every ten seconds; observations expire
after two minutes and reachability results are rechecked after a minute. Candidate
sets are sorted, deduplicated and bounded. A changed set refreshes the handlers used
for future direct negotiation, without dropping a healthy direct path.

Failed direct requests retire the failed direct connection, allowing the normal
bounded scheduler to retry through the retained relay route. Relayed-only trusted
peers get bounded periodic direct retries (roughly once a minute). Those retries
may briefly recreate an endpoint circuit; durable transfer IDs and destination
receipts handle ambiguous network results without repeating native submission.

A healthy direct connection continues carrying messages even if its discovery
hint expires or the operator becomes unavailable. The worker derives temporary
routes from its authenticated live connections rather than requiring a fresh
rendezvous record for every message. Those routes are never persisted and disappear
when the connection/trust disappears. New contact after a complete disconnection
still needs an available configured route or helper.

Public IP, mapping and listener changes retain persistent peer identities, grants
and destination-session pinning. Queued messages survive the path change and keep
the same immutable transfer IDs. Restart, disablement and revocation keep their
existing semantics: pending pairing approvals do not survive restart, networking
disable stops transport tasks, and revocation blocks access on all paths. Already
submitted native work cannot be recalled.

## Probe and destination limits

AutoNAT client handlers are restricted to configured infrastructure identities;
DCUtR handlers are restricted to trusted endpoints. Normal message access remains
separate. Raw Identify address lists and arbitrary discovery claims are not
imported as automatic direct routes. Own mapping observations come only from the
authenticated direct connection to a configured observer.

Automatic direct candidates require concrete IP/UDP/QUIC addresses and correct
endpoint identities. Loopback and private-network exceptions are limited to
explicit local/private infrastructure deployments. Link-local addresses (including common metadata endpoints),
unspecified, multicast, malformed and IPv4-mapped/compatible IPv6 bypass forms are
rejected. Public candidates are preferred over mixed public/private sets, avoiding
unnecessary disclosure of private hints to public peers.

The client keeps at most eight own candidates. Negotiation dial attempts and
bookkeeping are bounded per peer and globally. The public node permits at most
16 outstanding/active AutoNAT dialbacks, four dialbacks per peer per minute and
256 globally per minute. Callback destinations must match the requesting peer's
authenticated observed IP **and UDP port**, with no arbitrary host/port probes.
AutoNAT v2 preserves its fresh-port dialback and anti-amplification exchange.
Completed callback connections are closed individually, preserving the original
relay/control connection and its capacity for later checks.

The vendored AutoNAT/DCUtR patches add bounded candidate replacement/rechecking,
stale-nonce rejection and connection/queue/attempt cleanup. They do not change the
wire protocols or cryptography. Their provenance, original source/license notices,
upstream tests and patch notes are retained. Independent application review does
not replace the external audit planned for release readiness.

## NAT acceptance matrix

The optional Linux harness creates five nested namespaces: two endpoints, two
independent NAT routers and one relay connected through an isolated public fabric.
It uses outbound SNAT and connection tracking, with no static inbound DNAT or
port-forwarding rules. A same-socket UDP probe independently confirms the friendly
or restrictive topology before the product runs.

```sh
cargo build --locked
python3 tools/test_nat_traversal.py --binary "$PWD/target/debug/agent-bridge"
```

Scenarios can be selected with `--scenario direct`, `restricted` or `rebind`:

| Scenario | Required evidence |
| --- | --- |
| Direct | Both endpoints hole-punch, then exchange message/ACK/reply after relay UDP is blocked and rendezvous records expire. |
| Restricted | An actual hole punch fails, both paths remain relayed, and message/ACK/reply work. |
| Rebind | A blocked direct path falls back to relay, upgrades again after reopening, then survives a public-IP/listener change with one queued delivery, unchanged keys/grants and recovered direct connectivity. |

Each scenario checks private-session exclusion and revocation. Owners are simulated
only for disposable test brokers. Logs, hashes, firewall counters and JSON results
are retained under `/tmp/ab-nat-matrix-*`. Namespace guards precede network changes;
cleanup stops test processes. `--topology-only` is a diagnostic mode and explicitly
does not claim product acceptance.

These are isolated Linux virtual-network results, not physical cross-ISP, all
router models, IPv6-only, macOS or minimum-Rust acceptance. Milestone 5 adds separate
simulated blocked-UDP TCP acceptance; an external security audit and broader
supported-platform QA remain later work.
The single-binary local message monitor remains milestone 7.
