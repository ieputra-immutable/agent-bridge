# Machine names and peer identity

Each bridge has a persisted machine display name. It defaults to the short operating-system hostname on first initialization and can be changed explicitly. Sessions hosted by that bridge share its name; their session identities remain independent.

```sh
agent-bridge machine show
agent-bridge machine set-name machine-b
```

Names use 1–100 ASCII letters, digits, dots, underscores or hyphens. The reserved names `.` and `..` are rejected. Hostname defaults are sanitized, shortened to the first DNS label, and saved once. Changing the operating-system hostname later does not silently rename the bridge. Copying a state directory copies its configured name as well as its private key and trust records.

## Identity display and aliases

| Field | Meaning |
| --- | --- |
| `peer_id` | Cryptographic bridge identity, used for authenticated connections and routing. |
| `machine_name` | The bridge owner's configured display name. Remote stored values come from an authenticated metadata exchange. |
| `peer_alias` or peer record `alias` | Your local routing label for another bridge. An explicit alias takes display precedence. |
| `machine_display_name` or peer record `display_name` | Human-readable label, with a peer-ID suffix when needed to distinguish duplicate names. |

Names belong to bridge instances, not globally registered machines. Two OS users or two state directories on the same host can have the same name and different peer identities. Duplicate names are disambiguated with suffixes from the end of their peer IDs, lengthened if needed. Permission decisions always use the complete peer ID and pinned session identity.

`list` includes the local machine name and peer ID on each agent record. `list --remote` includes each remote agent's last authenticated machine name, peer ID and owner-local alias. Local-only use can show a null peer ID until an identity is created with `identity show` or networking is enabled; local messaging does not require creating a network key.

Message API results and native delivery envelopes include `source_machine` and `destination_machine` objects with `peer_id`, `machine_name`, `peer_alias` and `display_name`. The canonical sender, recipient and reply IDs remain unchanged. Native startup hooks also include local machine metadata when supported by the broker.

## Discovery and pairing

LAN discovery includes a bounded optional machine name alongside public identity and address hints. Announcements are unencrypted and unauthenticated. They expose the configured machine name to nearby network participants while LAN mode is enabled.

`peers discover` shows the advertised `machine_name`, its `machine_display_name`, and any separately stored `authenticated_machine_name`. `verified_advertisement` remains false even for a trusted peer: another device can forge a multicast claim, but cannot complete the QUIC handshake as that peer without its key.

Names are accepted only for the matching peer ID and address record. Malformed, oversized, conflicting or reserved optional names are ignored without discarding otherwise valid address hints. A name-only update cannot create a peer, extend an address lifetime, grant trust or rewrite an authenticated name.

After verifying a discovered peer's complete fingerprint through a trusted channel, pair normally:

```sh
agent-bridge peers pair PEER_ID --fingerprint VERIFIED_FINGERPRINT
```

If this is a new pairing with an advertised name, the bridge uses an available version of that name as the local alias. Collisions receive a peer-ID suffix. Use `--alias machine-b` to choose your own label. Existing aliases are preserved when pairing again without an explicit alias. This convenience does not authenticate the discovery announcement; the peer ID remains the verified identity.

## Authenticated names and renaming

Paired peers exchange names over their authenticated encrypted connection. An untrusted discovery claim never updates the stored remote machine name. Remote names are self-chosen labels asserted by the authenticated bridge; they are not an attestation of a physical machine's operating-system hostname.

New peers normally refresh authenticated names within five seconds while connected. An older peer can reject the optional metadata operation and continue exchanging the original version 1 messages, directories and receipts. Its authenticated name may remain unknown; local aliases and peer IDs still work.

Renaming preserves keys, peer IDs, pairing grants, session IDs, immutable queued envelopes and reply correlation. It refreshes the transport and its LAN advertisements, so a short reconnection can occur. Pending transfers retain their IDs and deduplication guarantees. A remote rename updates its stored machine name without changing an existing local alias or redirecting queued work.

## Encryption and upgrade

Bridge-to-bridge protocol traffic, including messages, receipts and authenticated machine metadata, uses encrypted QUIC connections authenticated by peer keys. Pairing determines which identities may connect; grants control which sessions may be discovered or messaged. Unencrypted mDNS discovery exposes public peer IDs, address hints and the optional display name.

Schema 5 adds the local name setting and optional authenticated peer-name column. Stop the service and back up the whole state directory before upgrading. Previous migration-aware binaries reject this newer schema; rollback requires restoring the pre-upgrade backup. The message wire envelope and its persisted deduplication contents are unchanged.
