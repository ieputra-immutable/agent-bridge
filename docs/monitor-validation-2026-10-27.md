# Local monitor validation

The monitor milestone passed 178 application tests. Data tests verify immutable
session metadata, preview/full-body separation, filters/pagination, migration and
reads without delivery-state mutation. HTTP tests cover bearer auth, exact
Host/origin/fetch metadata, response policies, read-only methods, query bounds,
port failures, stream shutdown and access rotation.

Nine Chromium/P2P acceptance checks passed again on the security-remediated
source: real local and peer inbox messages, ACK/reply/session provenance,
full details and reply navigation, filtering/live updates, literal HTML safety,
authentication/logout/revocation, no external assets and no body/token logging.
Desktop and mobile-width layouts were visually inspected.

```sh
cargo build --locked
python3 tools/test_monitor.py --binary ./target/debug/agent-bridge --browser
```

This uses disposable state and an already installed Playwright/Chromium. It does
not install a browser, start model sessions or validate macOS/native-agent UI.

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
