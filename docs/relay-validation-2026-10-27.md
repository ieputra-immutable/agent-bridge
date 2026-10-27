# Relay validation

Tests cover configured operator/final endpoint pins, bounded reservations and
registrations, two-owner pairing without implicit grants, session privacy,
message/ACK/reply correlation, independent operator failure and same-key restart.
The original relay milestone passed 142 application tests and 26 standalone
rendezvous tests. Source notices and patch descriptions are retained in `vendor/`.

Disposable namespace acceptance models separate outbound-only NAT networks:

```sh
cargo build --locked
python3 tools/test_relay_nat.py --binary ./target/debug/agent-bridge
```

These are virtual-network results, not physical Internet/platform acceptance.

## Reproduce automated checks

```sh
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

The latest complete application run passed 184 tests, with three multicast-sensitive
cases ignored. Historical milestone counts below describe their original scope.
Private machine identities, session identifiers, test bodies, paths and raw QA
artifacts are intentionally excluded from the public repository.
