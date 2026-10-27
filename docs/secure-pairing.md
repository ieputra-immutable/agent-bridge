# Secure mutual pairing

Each bridge has a persistent Ed25519 private key and a public peer ID. QUIC
connections authenticate that identity and encrypt messages, receipts and machine
metadata. LAN discovery is public and unauthenticated: it can help locate a
machine, but cannot authorize it. Machine names are display labels.

## Pair two machines

With the broker running on each machine, show their identities:

```sh
agent-bridge identity show
```

Compare each complete fingerprint using a channel you already trust: for example,
read it from the other machine's screen or use an existing authenticated SSH
connection. A fingerprint copied from an untrusted discovery announcement is not
verification. Signatures prove key ownership, not that the key belongs to the
machine you intended. There is no central account or trust server.

On machine A, create an offer:

```sh
agent-bridge peers offer --seconds 120
```

The result contains `offer`, A's `fingerprint`, a cancellation `nonce`, and
`expires_at` in Unix milliseconds. Transfer the offer to B through the trusted
channel. On B, pipe just the offer token to:

```sh
agent-bridge peers join --fingerprint VERIFIED_A_FINGERPRINT --alias workstation
```

If using an interactive terminal, paste the token, press Enter, then Ctrl-D.
Alternatively, pass the token as a positional argument; stdin avoids putting it
in shell history and process arguments. Input is bounded. The result contains a
signed `response`, B's `fingerprint`, and the paired issuer in `peer`.

B now trusts A locally. `mutual_pairing_complete: false` means A still needs to
finish. Return the response to A and verify B's fingerprint independently. Pipe
just the response token to:

```sh
agent-bridge peers finish --fingerprint VERIFIED_B_FINGERPRINT --alias laptop
```

`local_pairing_complete: true` confirms that A committed trust in B. It does not
mean B is currently online or that any native agent has accepted a message.
Inspect either side with `agent-bridge peers list`. Aliases are optional local
routing labels and never substitute for fingerprints.

The response signs the exact offer, the issuer identity and the responder's key
and address hints. The issuer commits trust and consumes the offer in one SQLite
transaction. Only one responder can complete a given offer, even if several
machines obtained a copy. A response from a different key fails the expected
responder fingerprint check. Failed validation or alias collisions do not consume
the offer.

## Expiry, cancellation and recovery

Offers last 30–600 seconds, defaulting to 120. Both machines must finish before
expiry and have reasonably accurate clocks. Pending offers survive broker
restarts. Each side retains at most 1024 active pairing records, pruning expired
records during new pairing operations.

On the issuer, invalidate an outstanding offer with:

```sh
agent-bridge peers cancel-offer NONCE
```

Cancellation prevents completion at A; it cannot undo trust already recorded at B
by `join`. Likewise, expiry stops new completion, rather than revoking trust
already established. To undo trust, run `peers revoke PEER` on each relevant
machine. No offline protocol can remotely undo a counterpart's trust decision.

Finish rejects an already consumed response. If its output was lost, inspect
`peers list` before starting another exchange. Replaying old tokens cannot restore
a revoked pairing. If you lose the join response, rerun the same join on B
before expiry with the same fingerprint and alias; the bridge returns its saved
response, including after restart. This cannot change the alias or restore revoked
trust. If the offer expires, cancel it where possible and create a fresh one.
Re-pairing a revoked peer requires fresh session grants.

## Permit only the sessions you need

Pairing opens no network listeners, changes no native application permissions and
grants no access to new peers. Existing nonrevoked peer grants are preserved when
repeating an explicit pairing. Enable LAN networking on both sides when ready:

```sh
agent-bridge network enable --lan
```

Choose local sessions with `agent-bridge list`, then explicitly grant the intended
peer `discover`, `receive` and/or `send` for those sessions using `peers allow`.
See [the permission table](peer-trust.md#grant-access-to-one-session). New sessions
do not inherit grants. Each side controls its own grants; revocation clears them.

Pairing imports the first signed direct-IP address hint only when there is no
existing manual address. These hints do not replace identity checks. LAN discovery
can supply newer hints automatically after trust is established. Without discovery
or a reachable signed hint, configure a direct address separately. Internet NAT
traversal and relays remain unimplemented.

## Security boundary

This flow uses the existing Ed25519 identity and encrypted, authenticated QUIC
transport. It introduces no unauthenticated remote pairing endpoint, shared
password, automatic LAN trust, router port mapping or central service. Offer and
response tokens are signed metadata, not confidential containers; they expose
public identities, timestamps and optional network addresses. Keep the channel
trusted to prevent substitution and unwanted pairing attempts.

Local administration trusts processes running as the same OS user. Protect the
private state directory and its backups. A compromised endpoint or stolen private
key can impersonate that machine; this protocol cannot prevent that. Received
agent messages remain untrusted input and do not grant native execution approval.

Legacy `peers invite` / `peers accept` remain compatible, but are unilateral and
only enforce replay protection per receiving database. Use `offer`, `join` and
`finish` for issuer-enforced single-use mutual setup.

Before upgrading to schema 6, stop the service and back up its complete state
directory, including WAL/SHM files. Rollback requires restoring the pre-upgrade
backup. See [upgrade guidance](peer-trust.md#upgrade-and-rollback).
