# Security review: Protocol and trust

Reviewed remote identity/authentication, key substitution, SAS commitments/MACs,
owner confirmation, signed contacts/invitations, replay/revocation, admission
versus application grants, configured operator/final endpoint pins, discovery,
relay behavior and AutoNAT/DCUtR candidate/callback scope.

No confirmed exploitable protocol/trust vulnerability was found in the examined
scope. An independent selection of 70 regression tests passed, including hostile
pairing/contact input, cancellation/revocation, exact key pins, network protocol
scope and transport fallback. Source review included the bounded vendor patches.

Receipt synchronization after unsharing reveals only a sender's prior delivery
status, not arbitrary history. Pairing windows and public relays still expose
bounded availability/metadata risks. A paired host vouches for its source agents;
cryptographic identity cannot prevent prompt injection or a compromised endpoint.

## Verdict and limits

The scoped review approved the remediated implementation with no remaining
confirmed material findings in its scope. It is an independent internal agent
review, not an external audit, exhaustive fuzzing/formal proof or a guarantee of
no vulnerabilities. See [the consolidated report](security-review.md) for findings,
fixes, dependency advisories and remaining native/platform acceptance limits.

Machine-specific logs, paths, identities and test artifacts are kept private.
