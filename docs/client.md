# Client

The client connects to the server over WebSocket, forwards public requests to
your local app(s), and runs a terminal UI plus a local inspection dashboard.

## Flags

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--server` | `MABO_TUNNEL_SERVER` | `ws://localhost:8080` | Server WebSocket URL |
| `--token` | `MABO_TUNNEL_TOKEN` | (required) | Auth token |
| `--port` | — | (required) | Ports to expose (see formats below) |
| `--subdomain` | `MABO_TUNNEL_SUBDOMAIN` | (random) | Request a specific subdomain (single port only) |
| `--protocol` | `MABO_TUNNEL_PROTOCOL` | `http` | Tunnel protocol: `http` or `tcp` |
| `--auth` | `MABO_TUNNEL_AUTH` | — | HTTP Basic Auth on the tunnel (`user:pass`) |
| `--config` | — | `mabo-tunnel.yml` | Path to a YAML config file |
| `--header-add` | — | — | Add/override a header on proxied requests (`"X-Foo: bar"`), repeatable |
| `--header-remove` | — | — | Remove a header from proxied requests (`"Cookie"`), repeatable |
| `--version` | — | — | Print version and exit |
| `--upgrade` | — | — | Self-update this binary from GitHub Releases, then exit |
| `--force-upgrade` | — | — | With `--upgrade`: reinstall even if already up to date |

Precedence: **CLI flag → YAML config → env var default**. `--token` and
`--server` fall back to the config file; `--port` (or config `tunnels`) is
required.

## Self-updating

```bash
mabo-tunnel-client --upgrade
```

Downloads the latest release asset for your platform from
[GitHub Releases](https://github.com/maborak/mabo-tunnel/releases), verifies it
against the release's `SHA256SUMS.txt`, and atomically replaces the running
binary. Restart afterwards to run the new version.

- Needs no token, port or config file — it short-circuits before any of that.
- Dev builds (`git describe` output, `dev`) always install the latest release.
- The unauthenticated GitHub API allows 60 requests/hour per IP; set `GH_TOKEN`
  to raise it to 5,000/hour. While this repository is **private**, a token is
  required for `--upgrade` to see releases at all.
- Do **not** use it inside Docker (the swap lives only in the container's
  writable layer — rebuild the image instead) or for Homebrew-managed installs
  (it would desynchronize brew).

## Port formats

`--port` is comma-separated; each entry is `[name:][host:]port`:

```
--port=3000                          # localhost:3000, random subdomain
--port=api:9001                      # named "api" → subdomain username-api, localhost:9001
--port=ui:192.168.0.40:5173          # named "ui" → forwards to a remote host
--port=ui:5173,api:9001              # two tunnels at once
--port=ui:192.168.0.40:5173,api:9001 # mixed local + remote
```

- Ports must be `1–65535`; invalid entries are skipped with a warning.
- `--subdomain` cannot be combined with multiple ports — use named tunnels.
- Default forward host is `localhost` when no host segment is given.

## Examples

```bash
# Single port
./build/mabo-tunnel-client --token=YOUR_TOKEN --port=3000

# Named, multiple ports
./build/mabo-tunnel-client --token=YOUR_TOKEN --port=ui:5173,api:9001

# Forward to a remote host on your LAN
./build/mabo-tunnel-client --token=YOUR_TOKEN --port=myapp:192.168.0.40:5173

# Protect the public endpoint with Basic Auth
./build/mabo-tunnel-client --token=YOUR_TOKEN --port=3000 --auth=admin:secret

# Stable subdomain
./build/mabo-tunnel-client --token=YOUR_TOKEN --port=3000 --subdomain=myapp

# Add/strip headers on the way to the local app
./build/mabo-tunnel-client --token=YOUR_TOKEN --port=3000 \
  --header-add="X-Env: staging" --header-remove="Cookie"

# TCP tunnel (e.g. PostgreSQL)
./build/mabo-tunnel-client --token=YOUR_TOKEN --port=5432 --protocol=tcp
```

## YAML config

By default the client looks for `mabo-tunnel.yml` in the working directory (missing
file is fine). An explicit `--config path` errors if the file is absent.

```yaml
server: wss://tunnel.example.com
token: your-token-here

tunnels:
  frontend:
    port: 5173
    host: 192.168.0.40      # optional, default: localhost
    auth: admin:secret       # optional, per-tunnel HTTP Basic Auth
    headers:
      add:
        X-Custom: value
      remove:
        - Cookie
  api:
    port: 9001
```

- Each key under `tunnels` becomes a named tunnel (`username-<name>`).
- CLI `--port` overrides the config's `tunnels` entirely.
- CLI `--header-add` / `--header-remove` extend/override YAML headers.
- Per-tunnel `auth` overrides the CLI `--auth` for that tunnel.

See [`mabo-tunnel.yml.example`](../mabo-tunnel.yml.example).

## Header handling

When forwarding to the local app the client:

- strips hop-by-hop headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`,
  `Upgrade`, `Te`, `Trailer`, `Proxy-Authenticate`, `Proxy-Authorization` — the
  set is shared with the server via `protocol.HopByHopHeaders`),
- forwards the server's `X-Forwarded-For` chain untouched (the server appended
  the verified public origin before sending; overwriting it here would erase
  that), sets `X-Forwarded-Host`, and `X-Forwarded-Proto: https`,
- applies your `--header-remove` (first) then `--header-add`.

## Web dashboard

The client starts a local dashboard on a random port (shown in the TUI). Open
it to inspect traffic. Endpoints (JSON, `Access-Control-Allow-Origin: *`):

| Method & path | Purpose |
|---------------|---------|
| `GET /_dashboard/` | Dashboard UI |
| `GET /_api/tunnels` | List local tunnels + request counts |
| `GET /_api/tunnels/{id}` | One tunnel's info |
| `GET /_api/tunnels/{id}/requests` | Request summaries (newest ring buffer) |
| `GET /_api/tunnels/{id}/requests/{rid}` | Full captured request/response |
| `POST /_api/tunnels/{id}/requests/{rid}/replay` | Replay a captured request through the tunnel |
| `GET /_api/status` | Uptime + active tunnel count |

The UI supports filtering by method / status class / path search, viewing
request and response bodies with JSON pretty-printing, replaying requests, and
copying as cURL / fetch / wget.

Capture limits: **100 requests per tunnel** (ring buffer) and **64 KiB per
body**, all in memory — nothing is persisted to disk.

## TUI

Shows, per tunnel: both HTTPS and HTTP URLs, the local target, a color-coded
request log, the dashboard URL, the authenticated username, and live ping
latency. Press `q` or `Ctrl+C` to quit — the client sends a graceful close so
the server releases the subdomain immediately.

## Reconnection

If the connection drops the client reconnects automatically with exponential
backoff (1s → ×2 → 60s cap, unlimited retries) and re-presents its
`session_id`, so it reclaims the same subdomain within the 5-minute reservation
window. See [architecture.md](architecture.md#reconnection--session-persistence).

---

**More:** [architecture](architecture.md) · [protocol](protocol.md) ·
[server](server.md) · [client](client.md) · [deployment](deployment.md) ·
[security](security.md) · [development](development.md) · [FAQ](faq.md) ·
[troubleshooting](troubleshooting.md)
