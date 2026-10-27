# Local patch: libp2p-dcutr 0.15.0

Source: crates.io libp2p-dcutr 0.15.0, MIT, upstream rust-libp2p. Original source,
license notices, Cargo.toml.orig, tests and upstream revision in .cargo_vcs_info.json
are retained. LICENSE reproduces the original source MIT notice.

Adds `set_address_candidates` to replace the local candidate LRU with at most eight
fresh addresses, preventing expired NAT mappings from persisting indefinitely.
Closed relay/direct connections prune associated pending dial mappings, retries and
queued work; dial failure removes the failed direct connection mapping immediately.
Handler attempt counters saturate and both inbound/outbound negotiation are capped
at the standard three attempts, preventing negotiated-stream floods from wrapping
counters or accumulating commands. The protocol and cryptography are unchanged. Agent Bridge separately gates handlers
to trusted endpoints and filters canonical outgoing QUIC destinations.

The standalone development manifest restores the published libp2p-swarm-test0.7.0
helper omitted from the normalized registry package, plus explicit test identity
features. Standalone checks:

```sh
cargo test --offline --locked --manifest-path vendor/libp2p-dcutr/Cargo.toml --target-dir target
cargo fmt --manifest-path vendor/libp2p-dcutr/Cargo.toml --check
cargo clippy --offline --locked --manifest-path vendor/libp2p-dcutr/Cargo.toml --all-targets --target-dir target -- -D warnings
```
