# Install Agent Bridge

The installer downloads a prebuilt executable and sets up a per-user service. It
does not need sudo, Rust, Node.js or a model API key.

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/jasadams/agent-bridge/main/install.sh | sh
```

This installs the **dogfood prerelease**, not an official stable release. Supported
platforms are Linux x86_64/arm64 with glibc 2.35 or newer, and macOS Intel/Apple
Silicon with macOS 13 or newer. Alpine/musl and older systems can build from source.
macOS binaries are ad-hoc signed, not Apple notarized.

The executable goes to `~/.local/bin/agent-bridge`. Add `~/.local/bin` to your PATH
if it is not already present. Linux uses a systemd user service named
`agent-bridge.service`; macOS uses the `local.agent-bridge` LaunchAgent. They start
at user login. A Linux systemd user session must be available; headless/container
setups can choose binary-only mode and run `serve` under their own supervisor.

```sh
agent-bridge status
agent-bridge monitor enable
```

Open the monitor's loopback URL and paste its separate access token. Tokens are
not embedded in URLs. Peer networking and monitor access remain independently
controlled. A fresh installation enables neither peer networking nor the monitor.
Open an existing Codex or Claude session to use native delivery. Claude registration
hooks can be installed separately with `agent-bridge hooks install`; hook trust and
native permissions remain your choices.

## Options and pinned builds

Pass installer arguments after `sh -s --`:

```sh
# Install the executable only, without touching services.
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/jasadams/agent-bridge/main/install.sh | sh -s -- --no-service

# Use a custom binary directory (binary-only mode).
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/jasadams/agent-bridge/main/install.sh | sh -s -- --no-service --bin-dir "$HOME/bin"
```

`--state-dir ABSOLUTE_PATH` selects service state. The existing default is
`~/Library/Application Support/AgentBridge` on both platforms, preserving deployed
identities and history. For an existing service using a custom state directory,
pass that same directory; the installer refuses ambiguous or mismatched service
state instead of risking a rollback against the wrong database.

`--version dogfood-COMMIT_PREFIX` pins an immutable published build. Use a tag listed
on the repository's prerelease page; the prefix is the first 12 hexadecimal commit
characters. The `dogfood` convenience channel moves only after all platform builds
and checks succeed. `status.build_commit` identifies CI-built source revisions.

## Updates, backups and removal

Run the same command again to update. A managed upgrade stops the previous service,
creates a private backup of its executable, service definition and complete state
(including SQLite WAL/SHM and identity), replaces the executable atomically and
checks readiness. If startup fails, it restores the old binary and matching state
before restarting the prior service. Backup paths are printed and retained under
`~/.local/state/agent-bridge-backups/`. Treat backups as private identity material.
Existing service environment/configuration is preserved on compatible upgrades.
No peer grants, trust, history, hook settings or native permissions are reset.

Binary-only installs retain the previous executable beside the destination.
They refuse to overwrite a configured managed installation, even when it is
stopped; choose a separate custom binary directory for a standalone copy. A binary-only update does not migrate state or restart a service.

```sh
agent-bridge service uninstall
```

Removal stops/unregisters the managed service and retains the executable, state,
history and backups. Hooks have a separate `hooks uninstall` command. Older binaries
must never open a newer schema; follow the [backup/rollback guidance](peer-trust.md#upgrade-and-rollback).

## Download integrity and licensing

The script uses HTTPS and verifies exact SHA-256 manifest entries for the binary,
GPL license, complete dependency notice bundle and source commit before executing
anything. Checksums detect corruption or a mixed download during channel updates;
they are not an independent publisher signature. As with any `curl | sh` command,
you are trusting this repository and its distribution account. You can download
and inspect the script before running it instead.

Versioned license notices are retained under
`~/.local/share/agent-bridge/licenses/COMMIT/` (or inside a custom binary directory's
`.agent-bridge-licenses/COMMIT/`). Each immutable prerelease provides its full
corresponding source, locked dependency sources and offline Cargo configuration.
The original project is GPL-3.0-or-later; dependencies retain their own licenses.

## Build from source

```sh
git clone https://github.com/jasadams/agent-bridge.git
cd agent-bridge
cargo build --release --locked
./target/release/agent-bridge service install
```

Dogfood CI uses Rust 1.98.0. Source builds need the platform C toolchain. The service
can run without a Codex executable installed; private native delivery requires a
compatible running native daemon and an already loaded destination session.
