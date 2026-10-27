# Shared Markdown board

The board is one local Markdown document shared by agents using this broker.
Its contents are entirely up to the user and agents: tables, notes, checklists,
headings or any other Markdown. Agent Bridge does not require task/status fields
or automatically change the content when an agent starts or stops work.

Open the live terminal view:

```sh
agent-bridge board
```

Use `j`/`k` or arrow keys to scroll, Page Up/Down and Home/End to navigate,
`h`/`l` to pan horizontally, `w` to toggle wrapping, and `r` to refresh.
Quit with `q`, Escape or Ctrl-C. File changes refresh the view automatically;
a brief broker outage keeps the last content visible and shows a retry status.
Extremely complex tables fall back to readable plain Markdown to bound rendering
work.

The broker must be running. Agents use the existing persistent MCP server and its
`read_board` and `update_board` tools. There is no extra server or binary.

For a custom broker state directory:

```sh
agent-bridge --state-dir "/absolute/private/state" board
```

The current document is stored as `boards/main.md` inside that private state
directory. A read of a missing document returns empty Markdown and its revision;
the first successful update creates it. Backups of the broker's state include the
board. Print its exact Markdown once with `agent-bridge board --raw`.

## Ask the agents to maintain it

For example, the user can instruct their agents:

> Keep our shared board up to date with a Markdown table. Give each agent one row
> containing its current task, status, whether it needs me, and a brief note.
> Update your own row when work changes. Preserve other agents' rows and notes.
> Read the latest board first, and retry conflicts against the returned revision.

Those columns are a user convention, not an application schema. The same tools
can instead maintain a release checklist, meeting notes or a project outline.
The board is user/agent-authored data and never grants tool permission or owner
approval.

## Incremental updates

`read_board` returns `markdown`, `revision`, `name`, `path` and `exists`.
`update_board` requires that exact revision and an ordered array of edits:

```json
{
  "expected_revision": "FULL_REVISION_RETURNED_BY_READ_BOARD",
  "edits": [
    {
      "op": "replace",
      "old": "| Agent A | Implementing | No |",
      "new": "| Agent A | Ready for review | Yes |"
    }
  ]
}
```

Available edits:

- `replace`: replace one unique, nonempty literal `old` with `new`.
- `append`: append `text` exactly as supplied.
- `prepend`: prepend `text` exactly as supplied.
- `set`: replace the document with `markdown`, useful for initial setup.

No automatic newline is added. Each batch contains 1–32 edits and applies in order
as one atomic file replacement. If any edit fails or the result exceeds 64 KiB of
UTF-8, nothing is changed. Ambiguous or missing replacement text is rejected;
select a complete unique row or section instead of a common word.

Concurrent agents cannot silently overwrite changes made through the broker.
A stale revision returns an MCP error with structured `conflict: true`,
`applied: false` and the current board snapshot. Review that snapshot and retry
only the intended edits with its revision. Do not replace the whole board using
an old copy. After an ambiguous transport failure, read the current document
before retrying an append or another edit.

## Local scope and future selection

This version exposes one local board named `main`. It does not synchronize the
file or grant board access to paired machines. Content storage, broker requests,
MCP tools and rendering are separate modules so a future board/source selector can
reuse the editor and viewer without imposing a content schema.

Manual file edits are possible, but external editors do not participate in the
broker's revision transaction. Coordinate manual changes with active agents to
avoid racing a file save against an MCP update. The live viewer is read-only;
terminal control sequences are removed for display, while the Markdown file
retains its original text. Links, HTML and images do not execute commands or fetch
network resources.
