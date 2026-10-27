# Security review: Browser and local OS boundary

Reviewed HTTP framing/methods/Host/Origin/fetch metadata, bearer credentials,
CSP/cache/referrer/frame protections, UI rendering/storage/logout/lifecycle,
query/connection/event limits, local IPC, native delivery and filesystem checks.

Two baseline confidentiality findings were confirmed and fixed: native Codex
message bodies in process arguments (medium, subject to OS process visibility),
and Claude pathname validation without a connected-peer UID check (low, requiring
a mutable ancestor of a custom socket path). The argv issue was demonstrated with
a disposable fake receiver. The socket finding was source-confirmed; no cross-user
exploit was executed. Fresh source/unit review approved both fixes.

No HTTP authentication, cross-origin, SQL injection or XSS bypass was found in the
examined scope. Eleven negative HTTP cases were rejected. Nine real Chromium/P2P
acceptance checks passed on the remediated binary, including detail/reply links,
filter/live updates, safe literal HTML, memory-only authentication and revocation.

## Verdict and limits

The scoped review approved the remediated implementation with no remaining
confirmed material findings in its scope. It is an independent internal agent
review, not an external audit, exhaustive fuzzing/formal proof or a guarantee of
no vulnerabilities. See [the consolidated report](security-review.md) for findings,
fixes, dependency advisories and remaining native/platform acceptance limits.

Machine-specific logs, paths, identities and test artifacts are kept private.
