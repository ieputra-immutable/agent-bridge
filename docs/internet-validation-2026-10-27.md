# Internet invitation validation

The invitation milestone passed 173 application tests. New coverage includes
canonical signed links, signature domain separation, expiry/bounds, independent
QR decoding, explicit atomic relay adoption, contact cancellation, bounded
identity-only lookup, TCP/DNS relaying and pinned reconnect routes after owner
verification.

Both disposable namespace scenarios passed, 18 checks total: application UDP
blocked with TCP relay fallback/operator failover; and DNS/public-address changes
with substitute-key rejection and same-key recovery. The DNS scenario permits
only its isolated fixture while blocking other application UDP.

```sh
cargo build --locked
python3 tools/test_internet_connectivity.py --binary ./target/debug/agent-bridge
```

These are simulated Linux networks, not physical multi-ISP/native-platform tests.

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
