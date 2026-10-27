# Internet invitations and restrictive networks

Milestone 5 adds signed contact links, local QR rendering, domain/IP first contact,
and encrypted TCP relay fallback. Everything runs in the existing binary. Endpoint
machines can connect using outbound connections; publicly reachable relay operators
still need reachable listeners. Operators are configured by their cryptographic
peer IDs, and can be self-hosted independently.

## Share a contact

Enable networking and configure one or more relay operators on the inviting machine
(see [public relays](public-relays.md)). Then run:

```sh
agent-bridge pairing invite --seconds 600 --qr
# Optional local SVG instead of the terminal QR:
agent-bridge pairing invite --seconds 600 --svg ./bridge-contact.svg
```

The command opens a temporary incoming pairing window and returns an
`agent-bridge://connect/…` link. SVG creation refuses to overwrite an existing file.
QR codes encode that exact link; rendering is local and needs no web service.
There is no camera scanner or operating-system URL-handler installation yet; paste
or pass a scanned link to the CLI.

On the other machine, enable networking and pass the link:

```sh
agent-bridge pairing connect 'agent-bridge://connect/…' --use-invite-relays
agent-bridge pairing list
```

`--use-invite-relays` explicitly chooses new or changed relay addresses carried by
that link. Omit it when all addresses are already configured. Adoption is atomic,
limited to four operators and up to two routes per operator (QUIC and TCP), and
creates no peer trust or session grants. A failed or expired pairing can leave
explicitly chosen relay configuration in place; inspect/remove it with
`network relays list/remove`.

The receiving owner accepts the pending request with `pairing accept ID`. Both
owners compare the verification code through a channel they trust and run
`pairing confirm ID --code CODE`. A signature proves control of the advertised key;
it does not prove who owns the machine. A link is reusable public contact metadata
until its 30–600 second expiry, not a bearer credential or one-time authorization.
Names are cosmetic. Existing [pairing](lan-pairing.md) and
[session sharing](session-sharing.md) controls still apply: paired sessions remain
private until explicitly shared. `pairing close` closes the incoming window and
cancels unfinished pairing. It does not erase copies of public contact metadata.

Links are capped at 2 KiB for a practical QR budget; very long relay addresses or
metadata can exceed that limit and must be shortened. A link without relay hints
can be used with LAN discovery. For Internet use, ensure
both endpoints have a working common relay route. The command starts an attempt;
use `pairing list` to inspect its progress.

## Start with a domain or IP

If a machine is directly reachable, its owner opens a temporary pairing window:

```sh
agent-bridge pairing open --seconds 120
```

The other owner can start with a location and an explicit port:

```sh
agent-bridge pairing connect 'bridge.example.net:44001'
agent-bridge pairing connect 'tcp://192.0.2.10:44001'
agent-bridge pairing connect 'quic://[2001:db8::10]:44001'
# Canonical /dns4/.../tcp/... and concrete-IP multiaddresses also work.
```

Bare `host:port` uses TCP. `quic://` selects UDP/QUIC; the target must actually listen
on that carrier. There is no implicit default port. DNS names use canonical lower
case ASCII (use punycode for international names). TCP listeners are supported by
`network enable --listen /ip4/0.0.0.0/tcp/44001`.

A bounded encrypted key lookup learns the initially unknown peer ID without
trusting it, sending application messages, or opening the caller's pairing window.
The normal two-owner verification follows. Only after successful verification is
the contact location saved for reconnecting with that peer ID pinned; an existing
manually configured route is preserved. DNS changes never authorize a new key.
A location alone cannot reach an endpoint behind NAT without a reachable listener;
use an invitation with relay hints for that scenario.

## Run a relay with both carriers

```sh
agent-bridge relay serve \
  --listen /ip4/0.0.0.0/udp/44001/quic-v1 \
  --advertise /dns4/relay.example.net/udp/44001/quic-v1 \
  --tcp-listen /ip4/0.0.0.0/tcp/44001 \
  --tcp-advertise /dns4/relay.example.net/tcp/44001
```

The relay prints its pinned peer ID. Configure both advertised addresses with
`network relays add ADDRESS/p2p/PEER_ID`. Listener addresses must be concrete IP
multiaddresses; advertised/dialed addresses can use DNS. One operator retains one
active reservation while the client prefers QUIC and falls back to TCP after a
bounded unsuccessful UDP attempt. Healthy TCP routes remain usable while clients
periodically retry QUIC. Configure additional independent operators for relay
outages; queued messages retry through remaining routes with durable transfer IDs.

QUIC provides authenticated encryption. TCP uses Noise and Yamux; relayed endpoint
traffic has its own authenticated Noise connection, so operators cannot read
message bodies. Operators can still observe identities, timing and traffic volume.
Encryption does not isolate against programs running as the same OS user or an
administrator on an endpoint. TCP fallback requires outbound TCP to a configured
operator; this milestone does not add HTTP proxy, TLS camouflage, Tor or WebSocket
transport. Direct NAT traversal remains best effort.

## Validation

`cargo test --locked` covers QR decoding with an independent decoder, signed-link
validation, schema upgrades, TCP/DNS transport, key pinning, owner verification and
contact route persistence. The disposable Linux namespace acceptance harness is:

```sh
cargo build --locked
python3 tools/test_internet_connectivity.py --binary ./target/debug/agent-bridge
```

It models separate NAT networks, blocks application UDP, and exercises relay
fallback/failover and DNS changes without modifying host networking. This is
simulated Internet acceptance, not a physical multi-ISP or macOS native-agent run.
See [the progress ledger](p2p-progress.md) for recorded results and remaining limits.
