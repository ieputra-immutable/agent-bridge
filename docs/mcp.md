# Agent tools through MCP

The same executable includes a persistent local MCP server:

```sh
agent-bridge mcp
```

An MCP-capable agent application launches this command once and keeps its standard
input/output connection open. Tools call the running broker through its private
same-user Unix socket. They do not start a shell or a new Agent Bridge executable
for each tool call. The broker service must already be running; the MCP process
does not start or take ownership of a model session.

The implementation uses the official Rust MCP SDK. This mode exposes stdio only;
it adds no HTTP endpoint or public network port. The existing CLI remains useful
for terminal use, scripts and recovery.

## Connect Codex

After installing a build containing MCP support, register the absolute executable
path with Codex:

```sh
codex mcp add agent-bridge -- "$HOME/.local/bin/agent-bridge" mcp
codex mcp list
```

For a custom state directory, include it in the server arguments:

```sh
codex mcp add agent-bridge -- "$HOME/.local/bin/agent-bridge" --state-dir "/absolute/private/state" mcp
```

Use `/mcp` in the Codex TUI to inspect active servers. Client configuration and
reloading follow the [official Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).
Adding the server does not grant blanket approval for its tools or change native
permissions. Other stdio-capable clients can launch the same absolute executable
with `mcp` as its argument and the optional `--state-dir` argument above.

## Connect Claude Code

```sh
claude mcp add --transport stdio --scope user agent-bridge -- "$HOME/.local/bin/agent-bridge" mcp
```

Use `/mcp` to inspect the server. Native session registration still uses the
lifecycle hooks described in [native session setup](native-sessions.md).
See the [official Claude Code MCP documentation](https://code.claude.com/docs/en/mcp)
for client scopes and approvals.

## Tools

| Tool | Purpose |
| --- | --- |
| `read_board`, `update_board` | Read and atomically edit the local shared Markdown board with revision checks. |
| `subscribe_board`, `unsubscribe_board` | Opt an exact local native session into or out of debounced board change notifications. |
| `connection_status` | Inspect the local broker and peer connections. |
| `list_agents` | List local sessions by default, or one explicitly selected peer's permitted sessions. |
| `list_messages`, `get_message` | Inspect message history and delivery state. |
| `send_message` | Persist a message with an idempotent UUID and optional reply ID and task outcome. |
| `acknowledge_message` | Confirm receipt separately from task completion. |
| `configure_network` | Explicitly enable or disable networking and LAN discovery. |
| `open_pairing`, `create_invite`, `connect_peer` | Organize pairing and choose the local session that receives owner prompts. |
| `pairing_status` | Inspect requests and their locally generated verification codes. |
| `confirm_pairing`, `cancel_pairing`, `close_pairing` | Apply the owner's decision or stop admission. |
| `share_session`, `unshare_session` | Explicitly grant or remove access to one selected local session. |

Tool inputs and results are structured JSON. Select the intended local registered
agent explicitly for sending, acknowledging, session sharing and pairing notices;
a server shared by several conversations must not guess which session owns a call.
Local registration names are available through `list_agents` or native registration
context. Pairing alone still shares no sessions.

Board subscriptions are off by default and end with the selected session or a
broker restart. Agents can use them to notice checkbox and text answers entered
in the TUI. Supply your own registered `agent` when calling `update_board` to
suppress notifications of your own writes. See [interactive board usage](board.md)
for the text-field syntax, debounce timing and concurrency behavior.

### Discover and share your session

Sessions remain private by default, including sessions created after pairing.
For local discovery call `list_agents({})`. Remote discovery requires a specific
paired peer alias or peer ID:

```json
{"peer":"workstation"}
```

This returns only that peer's permitted remote directory. There is no MCP option
to list every remote machine at once; the former `remote` boolean is no longer
accepted. Unknown or revoked peers return an error. A known peer with no shared
sessions returns an empty list, which does not prove that its local registration
failed. Results are cached and can briefly lag changes on the other machine;
their `online` field reports whether the peer is currently connected.

You can tell an agent **“Share this session with workstation.”** It should call
`share_session` using its own exact local registration name from its native
session context and the chosen paired peer:

```json
{"peer":"workstation","agent":"codex-<this-session-UUID>"}
```

The agent must resolve its actual name rather than submit the placeholder above
or select another conversation by guesswork. If its current session identity is
unavailable or ambiguous, it should clarify before changing access. The existing
MCP connection can serve several sessions, so it cannot infer a caller identity.

Sharing grants that peer discovery and two-way messaging for exactly the selected
local session. It does not share other or future sessions, and it does not change
the other machine's permissions. The other owner must also share their chosen
session for a two-way conversation. Use `unshare_session` with the same arguments
to remove this session's grants. An explicit local owner request authorizes the
selected action; a request received from a remote agent does not.

For a send, retain the returned message UUID. If the broker response is ambiguous,
retry with that exact UUID and the same message rather than generating another.
Submitted does not mean the other agent read the message or completed a task.
Acknowledgement confirms receipt only. To mark a reply as the final task report,
set `parent` to the message being answered and `outcome` to `succeeded` or `failed`:

```json
{"from":"reviewer","to":"requester","body":"Review complete","parent":"MESSAGE_UUID","outcome":"succeeded"}
```

`outcome` is optional and requires `parent`. It is the reply sender's report about
the parent task, separate from delivery state or acknowledgement. Message results
include `outcome` as null when unset. CLI sends use `--in-reply-to MESSAGE_UUID`
and `--outcome succeeded` or `--outcome failed`.

## Approval and transport boundaries

`confirm_pairing` requires the request ID, independently compared verification
code and an explicit `owner_confirmed: true`. A remote request, matching machine
name or notification is not owner approval. The boolean records the calling
agent's assertion; it does not cryptographically prove that a human consented.
Native client approval rules and explicit local owner instructions still apply.
The same OS user can already administer the broker through the CLI or private
socket, and MCP does not create a separate trust identity for that user.

Input framing, concurrent tool work and tool arguments are bounded. Broker-side
identity, expiry, replay protection, grants and native delivery checks remain the
source of authority. Peer metadata and message bodies in results remain untrusted
data. This is a local stdio integration, not an Internet-accessible MCP service.

Existing native message and pairing notifications remain responsible for waking
selected sessions. MCP tools provide commands and results; an MCP connection alone
does not guarantee that a client will turn arbitrary server notifications into a
new model turn. This mode does not replace the native delivery adapters.

Protocol references: [MCP stdio](https://modelcontextprotocol.io/specification/latest/basic/transports/stdio)
and the [official Rust SDK](https://github.com/modelcontextprotocol/rust-sdk).
