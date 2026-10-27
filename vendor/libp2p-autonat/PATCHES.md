# Local patch: libp2p-autonat 0.16.0

Source: crates.io libp2p-autonat 0.16.0, MIT, upstream rust-libp2p. Original source,
license notices, Cargo.toml.orig, tests and upstream revision in .cargo_vcs_info.json
are retained. LICENSE reproduces the original source MIT notice.

The AutoNAT v2 client gains `set_candidates` to remove expired mappings and queued
stale probes/confirmations without replacing active connection handlers, plus
`recheck_address` for completed/failed candidates. Pending nonce exchanges are not
reset. Incoming candidate storage is bounded to configured max_candidates (hard
cap64), and observation counters saturate. Agent Bridge uses an eight-candidate
limit and admits only its own canonical addresses observed by configured peers.
No protocol or cryptographic changes are made.

The standalone development manifest restores the published libp2p-swarm-test0.7.0
helper omitted from the normalized registry package, plus explicit test identity
features. Standalone checks:

```sh
cargo test --offline --locked --manifest-path vendor/libp2p-autonat/Cargo.toml --target-dir target
cargo fmt --manifest-path vendor/libp2p-autonat/Cargo.toml --check
cargo clippy --offline --locked --manifest-path vendor/libp2p-autonat/Cargo.toml --all-targets --target-dir target -- -D warnings
```
