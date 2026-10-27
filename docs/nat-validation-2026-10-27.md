# NAT traversal validation

The NAT milestone passed 155 application tests plus 25 AutoNAT and three DCUtR
standalone tests. The retained upstream dependency tests and patch descriptions
remain in `vendor/`; README documents their independent checks.

Three isolated namespace scenarios verified live direct communication after
relay/discovery loss, failed hole punching with encrypted relay fallback, and
public mapping changes with direct→relay→direct recovery. Keys, permissions,
durable message identity and acknowledgement/reply correlation were preserved.

```sh
cargo build --locked
python3 tools/test_nat_traversal.py --binary ./target/debug/agent-bridge
```

Physical multi-ISP/router, IPv6-only, macOS and minimum-Rust acceptance remain open.

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
