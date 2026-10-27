# Local patch: libp2p-rendezvous 0.18.0

Source: crates.io libp2p-rendezvous 0.18.0, MIT, upstream https://github.com/libp2p/rust-libp2p. Original copyright headers, manifest, tests and license retained.

Agent Bridge uses `client::Behaviour::without_address_cache()`: the client emits at most 256 registrations with TTL 1–300 seconds and at most four 512-byte addresses each, without internal address caches, per-record expiry futures or automatic dial hints. Application policy validates canonical relay paths and stores a bounded expiring cache.

Server renewal replaces old records and timers rather than accumulating inaccessible state; per-peer/global limits admit replacements and enforce exact capacity. Timers are stored by live registration identity, so unregister and renewal cancel them. Discovery pages are capped at 256 records and a conservative 48 KiB encoded budget (inside the 64 KiB frame); the application follows pagination cookies, cookies remain upstream's bounded LRU and remove obsolete registration IDs. Config can restrict the namespace. Signed envelopes are capped at 8 KiB. Signed address counts/lengths, request stream concurrency (16) and codec frames (64 KiB) are bounded.

Run this crate's own unit tests, formatting and Clippy separately when modifying this patch.

Standalone checks:

```sh
cargo test --offline --locked --manifest-path vendor/libp2p-rendezvous/Cargo.toml --target-dir target
cargo fmt --manifest-path vendor/libp2p-rendezvous/Cargo.toml --check
cargo clippy --offline --locked --manifest-path vendor/libp2p-rendezvous/Cargo.toml --all-targets --target-dir target -- -D warnings
```

The registry package contains MIT notices in each source file but no standalone license file; `LICENSE` reproduces that original notice. `.cargo_vcs_info.json` records the upstream revision. The standalone manifest enables Ed25519/random identity features for its existing unit tests and restores the published `libp2p-swarm-test` 0.7.0 helper for retained upstream integration tests (the registry-normalized manifest omitted this workspace path dependency).
