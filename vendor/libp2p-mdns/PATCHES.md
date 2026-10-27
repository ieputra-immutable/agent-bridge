# Agent Bridge mDNS patch

This directory contains the MIT-licensed source of `libp2p-mdns` 0.49.0 from the crates.io release. Upstream repository: https://github.com/libp2p/rust-libp2p, commit `7171dce2f90c05ba7892d4ba926abb1881db27c7`, path `protocols/mdns` (see `UPSTREAM.json`). Original copyright and license notices remain in every source file; `LICENSE` reproduces the license. `Cargo.toml.orig` is the upstream workspace manifest; the active manifest is the normalized published manifest with unused external test targets and dev dependencies removed, and identity test features enabled.

The application applies this crate through its Cargo patch entry. A standalone Cargo.lock is retained so the dependency's separate test commands work reproducibly with --locked. These are the intentional differences from the published source:

- Query and advertise `_agent-bridge._udp.local` instead of the generic libp2p service, with packet capacities derived from the service-name length. Discovery indicates protocol presence and exposes public peer IDs, address hints and an optional unverified machine display name.
- Add bounded `bridge-name=PEER_ID:NAME` TXT records tied to the same DNS instance and peer ID as its addresses. Names use 1–100 ASCII routing-label characters, excluding reserved `.` and `..` labels. Invalid, mismatched or ambiguous labels are ignored without discarding valid address hints. Name events follow address discovery and cannot establish trust.
- Abort interface tasks when the behaviour is dropped. Upstream Tokio task handles otherwise detach on drop, allowing old multicast work to survive network disablement.
- Bound internal discovered metadata to 1024 peer/address records, interface tasks to 32, interface send/discovery queues to 32 items each, and receive processing to 32 records per behaviour poll.
- Cap received record lifetimes to the configured TTL, prune expired records before processing refreshes, and report refresh events so the application's independent TTL cache can refresh live hints. Emit expiry before refresh when the same record expires and returns in one batch.
- Remove raw peer-address emission from the discovery behaviour. The application's `HintOnlyMdns` wrapper also suppresses automatic address contribution during dialing, ensuring only filtered LAN hints enter its dial requests.
- Add regression tests for hard metadata limits, expiry under continued refresh traffic, aborting tasks on drop, and the application-specific query service name. Existing upstream parser and packet tests remain enabled.

The application uses a 30-second TTL and 5-second query interval. Its separate user-visible cache allows 256 peers and four private or link-local IP QUIC addresses per peer. Discovery never changes the authenticated transport allowlist.

Validate the patched crate independently with:

```sh
cargo test --offline --manifest-path vendor/libp2p-mdns/Cargo.toml --features tokio --lib --target-dir target
```

Review these changes against a newer upstream release before removing or updating the patch. Retain the application-specific service name for discovery compatibility, task cancellation, bounded metadata, refresh/expiry ordering and filtered dialing semantics.
