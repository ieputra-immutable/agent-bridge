# Security review: Persistence, delivery and recovery

Reviewed schema migration/recovery, grants and session pinning, durable envelopes,
reply correlation, deduplication, ACK/status processing, retry semantics, native
framing and retained resource accounting.

Completed inbound history could grow without a retained byte/row limit despite
rate/pending limits (medium). The fix adds per-peer/global retained inbound quotas
and transactional usage counters without deleting history/deduplication records.
Native argv disclosure and the connected-socket user boundary were independently
assessed and their fixes approved. No additional confirmed state/authorization/
replay issue was found in the examined scope.

Forty-four independent targeted tests passed. New quota regressions cover UTF-8
and embedded-NUL bytes, both stored body copies, completed-message accounting,
schema-nine backfill, all four quota boundaries, no-write denial and idempotent
retries at capacity. Native tests cover exact IDs/home/loaded-session checks,
no process fallback and uncertain acceptance without automatic retries.

## Verdict and limits

The scoped review approved the remediated implementation with no remaining
confirmed material findings in its scope. It is an independent internal agent
review, not an external audit, exhaustive fuzzing/formal proof or a guarantee of
no vulnerabilities. See [the consolidated report](security-review.md) for findings,
fixes, dependency advisories and remaining native/platform acceptance limits.

Machine-specific logs, paths, identities and test artifacts are kept private.
