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
| `connection_status` | Inspect the local broker and peer connections. |
| `list_agents` | Find local sessions or the permitted remote directory. |
| `list_messages`, `get_message` | Inspect message history and delivery state. |
| `send_message` | Persist a message with an idempotent UUID and optional reply ID. |
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

For a send, retain the returned message UUID. If the broker response is ambiguous,
retry with that exact UUID and the same message rather than generating another.
Submitted does not mean the other agent read the message or completed a task.

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
