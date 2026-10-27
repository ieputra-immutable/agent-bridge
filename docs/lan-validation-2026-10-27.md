# LAN validation

A two-machine Linux LAN acceptance exercise verified automatic discovery,
owner-controlled trust/session grants, inbox messages, correlated replies,
address changes and revocation. Later native Codex exchanges verified queued
receipt, acknowledgement and correlated replies using the earlier CLI adapter.
Those historical results do not validate the replacement private native queue.
The current native adapter still needs supported-platform acceptance.

No machine names, addresses, session UUIDs or real test-message text are published.
Strict offline, macOS and native Claude acceptance remain separate checks.
See [LAN messaging](lan-messaging.md) for the physical-machine checklist.

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
