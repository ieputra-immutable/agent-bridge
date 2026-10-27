# Implementation status

The public repository starts with the complete current source snapshot. Private
local development history and machine-specific QA artifacts are not published.

| Milestone | Status |
| --- | --- |
| Persistent identity and owner-approved pairing | Implemented |
| Explicit session sharing and connection controls | Implemented |
| Configurable self-hosted rendezvous and encrypted relays | Implemented |
| NAT traversal and direct/relayed fallback | Implemented |
| Signed contact links/QR, DNS and encrypted TCP fallback | Implemented |
| Security hardening and release acceptance | Three internal agent review perspectives completed; broader acceptance remains |
| Same-binary local message monitor | Implemented |

The three scoped reviews identified and fixed native argument disclosure,
connected-socket user validation and retained inbound history growth. See
[the security report](security-review.md). This is not an external audit or a
vulnerability-free guarantee.

Remaining acceptance includes physical Internet/router testing, supported native
Codex/Claude and macOS checks, an external human security audit and a supported
history retention/compaction workflow preserving replay protection. Publication
is source availability, not an official release or production-readiness claim.

The original code is GPL-3.0-or-later; third-party notices are retained.

## Portable dogfood installation

A POSIX installer selects prebuilt Linux/macOS x86_64/arm64 binaries, verifies
checksums and retains source/license notices before delegating transactional
per-user service setup. Linux systemd and macOS launchd upgrades stop before
private backup and restore matching binary/state on failure. Existing state,
identity, grants and service configuration are preserved. Binary-only installs
are available without service managers.

CI tests/builds all four platforms before publishing immutable per-commit dogfood
prereleases and updating the moving convenience channel. Corresponding source
includes locked dependency sources and offline build configuration. The source
revision is exposed in CI-built status metadata. See [installation](install.md).
This remains dogfooding, not an official stable release.

Native CI additionally exercises repeated threaded and separate-process identity
initialization with both process-local and filesystem serialization. A minimal
vendored relay fix prevents non-reservation connection closure from incorrectly
reporting a live reservation as closed; retained upstream tests and a focused
regression cover the event semantics. No relay wire protocol or trust policy is
changed.

## Native pairing prompts

A locally selected native session can receive bounded pairing control notices,
ask its owner Yes/No after independently comparing the displayed code, and receive
completion updates automatically. The notification path carries no arbitrary
remote message text and grants neither trust nor session access by itself. Manual
pairing remains available. See [owner-approved pairing](lan-pairing.md).
