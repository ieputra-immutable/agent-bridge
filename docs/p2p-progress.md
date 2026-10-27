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
