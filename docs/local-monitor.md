# Local message monitor

The same `agent-bridge` executable contains the HTTP server and all HTML, CSS and
JavaScript. It reads the running broker's existing message database; there is no
separate web process, Node.js runtime, CDN, asset download or model call.

With the broker running, enable it:

```sh
agent-bridge monitor enable
```

The command returns a loopback `url` and a separate `access_token`. Open that URL
in a browser and paste the token into the access field. The default chooses an
available port; use `monitor enable --port 44002` for a fixed one. It binds only
`127.0.0.1`, including when a fixed port is chosen. There is no remote bind option.

```sh
agent-bridge monitor status  # Listener state; no token
agent-bridge monitor access  # Retrieve URL/token via the private local socket
agent-bridge monitor disable
```

The monitor starts disabled after every broker restart. It can operate with peer
networking disabled. Repeating enable with the same requested port preserves the
current access; disabling it or choosing another port invalidates credentials and
closes existing browser streams. A port conflict reports an error without stopping
the broker. Enabling/disabling the monitor changes no machine pairing, session
sharing, delivery or network listener settings.

## Inspect messages

The feed shows local, inbound and outbound messages with machine, agent/session,
delivery state and timestamps. Filter by machine name/peer ID, agent/session,
state and creation-time range. Load older pages, select a message for its full
body/detail, and follow its parent or direct replies. Message previews are bounded;
the selected detail retains the full stored body. Live server-sent invalidations
refresh the current view, including state changes and correlated replies.

New local messages snapshot the source and destination session metadata when
created. Network transfers use their saved envelopes, preserving the actual pinned
sessions even after registrations change. Earlier local messages retain their saved
destination session, but historical source sessions were not recorded and appear
as unknown. Remote machine aliases/names are display labels, not proof of human
identity. The monitor never creates a peer identity just to display local messages.

All views are read-only. There are no browser send, acknowledge, retry, cancel,
pairing or grant controls. Receipt/submission states have their existing meaning;
monitoring does not establish that a model ran or completed a task.

## Browser access

API requests carry a random access token in an Authorization header. The page
keeps it only in memory; locking the monitor clears its message views and token,
and closing/reloading the page requires access again. Tokens do not appear in URLs,
query strings, cookies, referrers or browser storage. Static login assets contain
no message history or credentials.

Exact Host validation, Origin and browser fetch-metadata checks reject DNS rebinding
and cross-origin requests. The server supplies no CORS permission, rejects write
methods, uses restrictive content-security/frame/referrer policies and disables
caching. Message text renders as text, including HTML-like content. The server
logs neither message bodies nor HTTP requests/access tokens. Connection, header,
query, result-page and live-stream budgets constrain resource use.

This boundary does not protect against another process running as your OS user,
an administrator, or a privileged browser extension. Such processes may already
access the broker's private local socket or state. Keep the browser token private;
disable/re-enable the monitor to invalidate a copied token.

## Upgrade and validation

Schema 9 adds local message context snapshots and an ordered monitor index without
rewriting message bodies or delivery state. Follow the [backup/rollback guidance](peer-trust.md#upgrade-and-rollback)
before running this version on existing state. Reads share the broker's existing
connection and never open a second database through startup recovery.

Automated HTTP tests check authentication, origins/Host, read-only methods, bounded
filters, port errors and stream/key revocation. Data tests check historical session
pinning, pagination, preview/full body, migration and reads without delivery writes.
The disposable acceptance harness can exercise local and real peer messages and
an already installed Playwright browser without starting native model sessions:

```sh
cargo build --locked
python3 tools/test_monitor.py --binary ./target/debug/agent-bridge --browser
```

Omit `--browser` when Playwright and its matching browser are unavailable; that run
has no browser acceptance claim. No browser is downloaded by the harness.
