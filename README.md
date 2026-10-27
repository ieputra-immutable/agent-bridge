# Agent Bridge

A small Rust service for local and opt-in peer communication between **native Claude Code and Codex sessions** on macOS. Keep using their terminal and desktop interfaces. The bridge does not launch, wrap, or own an agent's model session, and it makes no model API calls.

```text
Native Claude / Codex
        │ agent-bridge send (or newline-delimited JSON)
        ▼
Private Unix socket → SQLite queue → native delivery adapters
                                     ├─ Claude Code inbox socket
                                     └─ private native Codex queue RPC
```

## Install

Linux and macOS (Intel and Apple Silicon), no sudo or Rust toolchain required:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/jasadams/agent-bridge/main/install.sh | sh
```

This installs the checked **dogfood prerelease** and starts a per-user service:
systemd on Linux, launchd on macOS. Existing identity, history and grants are
preserved; upgrades make a private backup before changing the running service.
`~/.local/bin` must be on your PATH. See [installation options and rollback](docs/install.md)
for supported versions, binary-only installs, immutable builds and source builds.

```sh
agent-bridge status
agent-bridge monitor enable
# Optional registration hooks:
agent-bridge hooks install
```

The service makes no model API calls. Native sessions retain their normal approval
and hook-trust settings. Networking and monitor access stay off on a fresh install
until explicitly enabled.

The hooks installer preserves existing hooks and settings, backs up existing configuration files, and adds registration handlers to `~/.claude/settings.json` and `~/.codex/hooks.json`. It changes no agent permissions or inbound messaging settings.

**Codex registration is automatic in 0.1.1.** The service connects to the existing native Codex daemon's private socket, discovers loaded sessions, and follows lifecycle and name-change events. It uses only metadata requests: it never starts, resumes, or takes ownership of a native session. `agent-bridge status` reports discovery connectivity.

Claude uses startup/end hooks to register and disable sessions. The optional Codex hooks also supply proactive messaging instructions; **Codex requires you to trust those entries in `/hooks` before they execute**, but discovery and receiving messages do not depend on those hooks. The bridge does not bypass hook trust. A crashed Claude application can leave a registration enabled; Codex discovery follows the daemon's loaded/unloaded state, which may outlive an open window.

**`agent-bridge list` shows enabled peers by default (0.1.3).** Exited registrations are retained internally for session identity and message history, but are omitted from peer discovery. Use `agent-bridge list --all` to inspect them. A restarted session can register again and reappear. An enabled Codex thread may still be loaded in its native daemon after its window closes; enabled indicates transport availability, not whether an agent is currently thinking.

Default IDs are `claude-<session-UUID>` and `codex-<thread-UUID>`. These are stable, unambiguous routing names. `list` also shows each session's `provider` (`claude` or `codex`), native `display_name`, and provider-qualified `qualified_name`; use that name directly in `send --to`, `--from`, `history --agent`, and `ack --agent`. Names containing spaces are accepted when shell-quoted. Duplicate native names are rejected as ambiguous; use the stable ID instead. Existing manually registered names take precedence over native name lookup.

For example, once your native Codex task is named `agent-bridge-test`, no registration command is needed:

```sh
agent-bridge list
agent-bridge send --to agent-bridge-test --message 'Please acknowledge and reply'
```

**Claude names update automatically in 0.1.2.** After `/rename agent-bridge-test`, peers see `display_name: "agent-bridge-test"`, `provider: "claude"`, and `qualified_name: "claude:agent-bridge-test"`. Use `send --to 'claude:agent-bridge-test'` to distinguish it from a Codex task with the same title (`codex:agent-bridge-test`). Duplicates within one provider still require the stable ID. Explicit registered aliases retain precedence for exact matches, so prefer qualified names when titles overlap with old aliases.

The service uses native filesystem notifications to follow title records in already registered Claude sessions under `~/.claude/projects` (or `$CLAUDE_CONFIG_DIR/projects`). It reads existing records once, then tails appended records on change, retaining only session titles and file offsets. It neither modifies transcripts nor requires a model call or a new hook definition. This internal Claude JSONL format is isolated in `src/claude_discovery.rs` because it may change between versions. Registration still uses the startup hook. Filesystem notifications can coalesce, so title updates may take a moment; unavailable watchers retry after 15 seconds.

Manual registration remains available for Claude and as a Codex fallback:

```sh
agent-bridge register codex reviewer --thread YOUR_THREAD_UUID

# Run inside the target Claude session's Bash tool:
agent-bridge register claude implementer \
  --session YOUR_CLAUDE_SESSION_UUID \
  --socket "$CLAUDE_CODE_MESSAGING_SOCKET"
```

Claude `/status` shows the session ID and peer socket address. For manual aliases, the native startup hook's name and the alias refer to the same session, but they are separate routing names. Prefer one name consistently. SessionEnd hooks unregister only the automatically generated name; disable a manual alias explicitly when finished.

## Agent permissions

Peer-to-peer development is tracked in [the implementation plan](docs/p2p-implementation-plan.md) and the agreed [seven-milestone public P2P roadmap](docs/public-p2p-roadmap.md). [Owner-approved LAN pairing](docs/lan-pairing.md), [single-use manual mutual pairing](docs/secure-pairing.md) and [identity and trust commands](docs/peer-trust.md) support [explicit-address messaging](docs/explicit-peer-messaging.md) and [automatic IPv4 LAN discovery](docs/lan-messaging.md), with encrypted connections and durable receipts. [Machine display names](docs/machine-names.md) default to the hostname and can be configured independently of cryptographic identity. [Session sharing and connection controls](docs/session-sharing.md) provide explicit two-way sharing for individual sessions. [Public rendezvous and self-hosted relays](docs/public-relays.md) provide outbound-only relayed connections through configurable operators. [Automatic NAT traversal](docs/nat-traversal.md) attempts direct upgrades and retains encrypted relay fallback, with direct/relayed status. [Internet invitations](docs/internet-invitations.md) add signed links and QR codes, domain/IP first contact, and encrypted TCP relay fallback for blocked UDP. Networking is opt-in. The [embedded local message monitor](docs/local-monitor.md) provides an optional read-only browser view of local and peer traffic, independently of networking.

There are three independent permissions: trusting a lifecycle hook, allowing a shell command, and allowing that command to connect to the broker socket. Native work permissions still apply to anything a received message asks an agent to do.

### Claude Code

The startup hook runs through Claude's normal workspace trust flow. Once the workspace is trusted, registration should appear in `agent-bridge list` without a model call. In the live setup test, startup registered the session and SessionEnd disabled it successfully.

Allow the messaging commands when Claude requests them, or merge narrowly scoped Bash rules into your existing permissions. Example configuration (replace `YOUR_USER` with your macOS account name):

```json
{
  "permissions": {
    "allow": [
      "Bash(/Users/YOUR_USER/.local/bin/agent-bridge list *)",
      "Bash(/Users/YOUR_USER/.local/bin/agent-bridge status *)",
      "Bash(/Users/YOUR_USER/.local/bin/agent-bridge send *)",
      "Bash(/Users/YOUR_USER/.local/bin/agent-bridge ack *)",
      "Bash(/Users/YOUR_USER/.local/bin/agent-bridge get *)",
      "Bash(/Users/YOUR_USER/.local/bin/agent-bridge history *)"
    ]
  }
}
```

These match the absolute command paths supplied by the bridge. If you instead use the short `agent-bridge` name, approve that spelling separately. Keep administrative commands such as `service`, `hooks`, `pause`, and registration replacement outside ordinary messaging grants. Merge with existing rules; do not replace your permissions object. [Claude Bash rule reference](https://code.claude.com/docs/en/permissions).

If Claude's Bash sandbox is enabled, it also needs this one socket in its existing sandbox configuration:

```json
{
  "sandbox": {
    "network": {
      "allowUnixSockets": [
        "/Users/YOUR_USER/Library/Application Support/AgentBridge/bridge.sock"
      ]
    }
  }
}
```

When inbound peer messages are held, check `/config` → **Messages from your other sessions**, or the effective `crossSessionInbound` setting. `accept` enables unattended receipt; it applies to cross-session messages generally, not only this broker. The installer leaves that choice unchanged. Claude's manual-mode default accepted the validation message. [Inbound controls](https://code.claude.com/docs/en/cross-session-messaging#control-inbound-messages), [sandbox configuration](https://code.claude.com/docs/en/sandboxing).

### Codex

Loaded native Codex sessions register automatically over the daemon's socket. No manual registration, hook approval, model call, or native app restart is needed for discovery. The observer uses `initialize`, `thread/loaded/list`, and `thread/read`, then waits for native lifecycle notifications. Reconnect backoff runs only while the daemon is unavailable; connected discovery has no timer or mailbox scan. The socket layout is isolated in `src/discovery.rs` because it can change between native Codex versions. Set `serve --no-discovery` to disable this observer.

For proactive messaging instructions at session startup, optionally open `/hooks`, review the two **Agent Bridge registration** handlers, and trust them. The installer neither marks them trusted nor uses a trust-bypass flag. Those hooks are a fallback and context helper; automatic discovery works independently.

In a restricted session, approve bridge commands through Codex's normal command dialog. The native round-trip test used one-time approval for the exact `ack` and `send` commands. Those approvals allowed the model to acknowledge a delivered message and return `BRIDGE_CODEX_OK` through the service.

For persistent socket access in a restricted native session, add a named profile to your existing `~/.codex/config.toml`. This example retains workspace editing, allows the one broker socket, and supplies no external command-domain grants:

```toml
[permissions.agent-bridge]
extends = ":workspace"

[permissions.agent-bridge.network]
enabled = true

[permissions.agent-bridge.network.unix_sockets]
"/Users/YOUR_USER/Library/Application Support/AgentBridge/bridge.sock" = "allow"
```

Use the profile in the native CLI with:

```sh
codex --enable network_proxy -c 'default_permissions="agent-bridge"'
```

For the native desktop application, the equivalent persistent configuration is `default_permissions = "agent-bridge"` at the top level and `network_proxy = true` in the existing `[features]` table; restart the app after changing it. Merge any command-domain access your workflow already needs into this profile. These are optional configuration changes, not changes the installer makes automatically. The proxy must be active for its socket allowlist to take effect. [Codex permission profiles](https://learn.chatgpt.com/docs/permissions).

This equivalent read-only sandbox check was verified locally:

```sh
codex sandbox --enable network_proxy \
  -c 'permissions.agent-bridge-check.filesystem={":minimal"="read"}' \
  -c 'permissions.agent-bridge-check.network.enabled=true' \
  -c 'permissions.agent-bridge-check.network.unix_sockets={"/Users/YOUR_USER/Library/Application Support/AgentBridge/bridge.sock"="allow"}' \
  --permission-profile agent-bridge-check \
  -C "$PWD" /Users/YOUR_USER/.local/bin/agent-bridge status
```

Without a socket allowance, the same restricted check returned `Operation not permitted`. A working connection needs no database write permission in the agent sandbox: only the background service accesses SQLite.

### First exchange

Once both native sessions are registered, ask the sending agent:

> Run agent-bridge list, send the other agent a short test message, and ask it to acknowledge and reply using the message ID. Use your registered name as the sender.

Confirm the original message becomes `acknowledged` in `get` or `history` and a reply has its ID in `parent`. A `submitted` record by itself is not a completed exchange. Neither agent should need a polling loop.

## Send and reply

```sh
agent-bridge list
agent-bridge send --from implementer --to reviewer --message 'Please review src/db.rs'

# Bodies can come from stdin so quotes and shell characters are preserved.
agent-bridge send --from reviewer --to implementer --in-reply-to MESSAGE_UUID <<'MESSAGE'
Review complete. The string $(example) here is literal text.
MESSAGE

agent-bridge ack --agent implementer MESSAGE_UUID
agent-bridge history --agent implementer
agent-bridge get MESSAGE_UUID
```

The default sender is `user`. Replies to `user` go into the broker's durable inbox; read them with `agent-bridge history --agent user`. No notifications are forwarded to Slack or any other external service.

Each native delivery includes the original sender, body, message ID, reply correlation, and commands to acknowledge or reply. Agents send explicit messages; their ordinary output is not automatically forwarded to another agent. Acknowledgements update database state and do not wake the sender, avoiding automatic acknowledgement loops. Correlated reply chains are capped at eight hops.

## Delivery semantics

| State | Meaning |
| --- | --- |
| `queued` | Committed to SQLite, waiting for submission. |
| `sending` | A native delivery adapter is running. |
| `submitted` | Written to Claude's socket, accepted by the private native queue, or stored in a broker inbox. **Does not establish native acceptance, agent receipt, or task completion.** |
| `acknowledged` | A command from the recipient's routing name confirmed receipt. This is not task completion. |
| `failed` | A definite pre-submission failure, such as a missing socket or executable. |
| `uncertain` | Delivery may have happened: a partial write, ambiguous Codex command result, or service interruption during submission. |
| `cancelled` | A queued message was explicitly cancelled. |

Claude can hold or refuse messages under its inbound controls. Both applications can be idle, busy, rate limited, or waiting on permissions. The service never interprets a successful socket write as proof of execution. It uses Claude's native peer-message path rather than injecting keystrokes or editing conversation history.

Messages are pinned to the destination session UUID. Replacing a routing name never redirects old queued messages to a new session. Per-recipient submissions run in FIFO order, with up to sixteen recipients submitting concurrently. This orders transport submissions, not model completion across applications.

Queued messages survive broker restarts. An in-flight message becomes `uncertain` after restart. Neither failed nor uncertain messages are automatically resent. Fix the endpoint and retry explicitly:

```sh
agent-bridge retry MESSAGE_UUID
# Only after checking the native conversation for an already delivered message:
agent-bridge retry MESSAGE_UUID --allow-duplicate

agent-bridge pause
agent-bridge resume
agent-bridge cancel MESSAGE_UUID
agent-bridge unregister implementer --session YOUR_CLAUDE_SESSION_UUID
```

The sender prints a generated UUID to stderr before its RPC call. If that RPC times out, repeat the same send with `--id THAT_UUID`: identical requests return the original record, while conflicting reuse is rejected. This avoids double-enqueuing after a lost broker response. It cannot make native model execution exactly once.

## Local socket protocol

State lives in `~/Library/Application Support/AgentBridge`, restricted to your OS user. `bridge.sock` has mode `0600`. The server verifies the connecting user's UID. Each connection accepts one UTF-8 JSON record followed by a newline and returns one JSON response followed by a newline:

```json
{"op":"send","id":"MESSAGE_UUID","sender":"implementer","recipient":"reviewer","body":"Ready for review","parent":null}
```

```json
{"ok":true,"result":{"id":"MESSAGE_UUID","state":"queued"}}
```

The full result is a message record. Other operations are defined by `Request` in `src/protocol.rs`. Message bodies are limited to 64 KiB; serialized requests to 256 KiB; pending queue to 1000 messages; history queries to 100 records. Consumers wait on socket events, with no mailbox timer or background model polling. Messages are retained until the database is removed; automatic retention and a menu-bar UI are not implemented.

Local administration has a **same-OS-user trust boundary**: processes running as your user can register names, send messages, and acknowledge them. Routing names are not cryptographic agent identities. Receiving applications retain their native permission checks. The broker opens a peer network listener only after `network enable`; model inference still uses each native application's normal provider connection.

## Run, inspect, remove

```sh
agent-bridge status
launchctl print gui/$(id -u)/local.agent-bridge
tail -f "$HOME/Library/Application Support/AgentBridge/service.stderr.log"

# Foreground development with isolated state:
agent-bridge --state-dir /private/tmp/my-private-agent-bridge serve

agent-bridge hooks uninstall
agent-bridge service uninstall
```

Uninstall leaves the binary, message database, and hook backups in place. `--state-dir` works on every command. The managed service uses explicit binary paths, so it does not depend on an interactive shell's environment.

For sensitive message bodies, pipe stdin into `send` rather than passing `--message TEXT`, which your OS may expose in process listings. The native delivery adapter never passes bodies in process arguments. See [the security review](docs/security-review.md) for the three review scopes, fixes and remaining acceptance limits.

## Validation

```sh
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
sh -n install.sh
python3 tools/test_installer.py
python3 tools/test_packaging.py
```

When changing the vendored mDNS dependency, also run its tests and checks separately; the root package checks do not cover dependency unit tests:

```sh
cargo test --offline --locked --manifest-path vendor/libp2p-mdns/Cargo.toml --features tokio --lib --target-dir target
cargo fmt --manifest-path vendor/libp2p-mdns/Cargo.toml --check
cargo clippy --offline --locked --manifest-path vendor/libp2p-mdns/Cargo.toml --features tokio --all-targets --target-dir target -- -D warnings
```

When changing the vendored rendezvous dependency, also run:

```sh
cargo test --offline --locked --manifest-path vendor/libp2p-rendezvous/Cargo.toml --target-dir target
cargo fmt --manifest-path vendor/libp2p-rendezvous/Cargo.toml --check
cargo clippy --offline --locked --manifest-path vendor/libp2p-rendezvous/Cargo.toml --all-targets --target-dir target -- -D warnings
```

When changing the vendored AutoNAT or DCUtR dependencies, also run their separate checks:

```sh
cargo test --offline --locked --manifest-path vendor/libp2p-autonat/Cargo.toml --target-dir target
cargo fmt --manifest-path vendor/libp2p-autonat/Cargo.toml --check
cargo clippy --offline --locked --manifest-path vendor/libp2p-autonat/Cargo.toml --all-targets --target-dir target -- -D warnings
cargo test --offline --locked --manifest-path vendor/libp2p-dcutr/Cargo.toml --target-dir target
cargo fmt --manifest-path vendor/libp2p-dcutr/Cargo.toml --check
cargo clippy --offline --locked --manifest-path vendor/libp2p-dcutr/Cargo.toml --all-targets --target-dir target -- -D warnings
```

Multicast-sensitive LAN checks and the physical-machine acceptance checklist are documented in [LAN messaging](docs/lan-messaging.md).

Tests cover real broker Unix sockets with a simulated Claude receiver, Codex argument handling without a shell, restart recovery, duplicate IDs, recipient replacement, FIFO submission, fast acknowledgements, pause/resume, reply-chain bounds, hook configuration preservation, endpoint permissions and malformed frames. Discovery tests use a simulated native WebSocket server to verify initial discovery, rename/close events, native-name lookup and duplicate-name rejection without starting or resuming a thread. Claude discovery tests cover native filesystem rename events, startup title loading, partial writes, replaced files, and provider-qualified lookup with cross-provider and manual-alias collisions. These tests require no model calls.

Live setup validation on 23 October 2026 additionally verified:

- The installed LaunchAgent started successfully and responded through its private socket.
- A native Claude Code 2.1.309 session registered through SessionStart, received the service's envelope and woke from idle, then disabled its registration through SessionEnd. Its model reply was blocked by the account session limit; a complete Claude model acknowledgement/reply remains unverified.
- A native Codex CLI 0.163.0 session received a queued message, acknowledged it with the bridge command, and returned a correlated `BRIDGE_CODEX_OK` reply to the user inbox.
- Killing the service process caused launchd to restart it. A paused, queued message survived and was submitted after resume.
- A restricted Codex sandbox connected successfully with the exact socket permission above, and failed without it.
- Version 0.1.1 discovered loaded sessions from the already running native daemon. A temporary rename of `agent-bridge-test` was observed automatically, and sending to that new native name resolved to its original session UUID. That validation message was cancelled before delivery and the original task name was restored; the check required no model inference or manual registration.

Version 0.1.2 also discovered an already running Claude session renamed `agent-bridge-test`, listed it with `provider: "claude"` and `qualified_name: "claude:agent-bridge-test"`, and submitted a user-requested terminal visibility test to that qualified name. The socket write completed in 11 ms; terminal display and a model reply were not independently verified.

The desktop UI was not separately exercised. Codex delivery now uses the existing daemon's private Unix-socket native queue, without putting message text in process arguments. Native compatibility of this security change still needs live platform acceptance. Claude's raw frame compatibility is version-dependent and isolated in `src/delivery.rs`.

References: [Claude local inbox sockets](https://code.claude.com/docs/en/cross-session-messaging#the-sessions-inbox-socket), [Codex queue](https://learn.chatgpt.com/docs/cli/reference), [Codex hook configuration and trust](https://learn.chatgpt.com/docs/hooks).

## License

Copyright (C) 2026 jasadams. Agent Bridge is free software, licensed under the
GNU General Public License, version 3 or (at your option) any later version
(`GPL-3.0-or-later`). See [LICENSE](LICENSE). Vendored third-party components retain
their original copyright and license notices; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
