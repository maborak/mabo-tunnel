# Architecture

Mabo Tunnel is a reverse tunnel service: a public **server** accepts internet
traffic and forwards it, over a single persistent WebSocket, to a **client**
running on your machine, which relays it to a local app.

```
                    PUBLIC INTERNET
   https://abc123.tunnel.example.com
              │  (HTTP / HTTPS / raw TCP)
              ▼
   ┌────────────────────────┐
   │   Mabo Tunnel Server       │   :8080 (HTTP)  :4443/:443 (HTTPS)
   │   - HTTP reverse proxy │   10000-10100 (TCP tunnels)
   │   - TCP proxy          │
   │   - WebSocket handler  │
   └───────────┬────────────┘
               │  ONE WebSocket per tunnel  (/tunnel/connect)
               │  JSON envelopes, multiplexed by conn_id
               ▼
   ┌────────────────────────┐
   │   Mabo Tunnel Client (CLI) │   your machine
   │   - reconnect/backoff  │
   │   - worker pool        │
   │   - TUI + dashboard    │
   └───────────┬────────────┘
               │  localhost:PORT (or remote host:port)
               ▼
        ┌──────────────┐
        │  Local app   │
        └──────────────┘
```

## Components

| Path | Responsibility |
|------|----------------|
| `cmd/server/main.go` | Server entry point, flag/env parsing, embedded-secret fallbacks |
| `cmd/client/main.go` | Client CLI, port-flag parsing, TUI + dashboard bootstrap |
| `cmd/embed-secrets/main.go` | Build tool: encrypt + embed AIO secrets into the server binary |
| `internal/server/server.go` | Lifecycle, HTTP routing, WebSocket upgrade, read/ping loops |
| `internal/server/tunnel.go` | Tunnel registry, subdomain assignment, quotas, TCP port allocation, stale cleanup |
| `internal/server/http_proxy.go` | Public HTTP → tunnel proxy, streaming responses, WS upgrade forwarding, IP/Basic-Auth checks |
| `internal/server/tcp_proxy.go` | Raw TCP listener per TCP tunnel, bidirectional relay |
| `internal/server/auth.go` | WebSocket auth handshake |
| `internal/client/client.go` | Connect/auth/reconnect, request forwarding, streaming, WS passthrough, TCP mode |
| `internal/client/tunnel.go` | Reconnect policy and exponential backoff |
| `internal/client/{dashboard,api,inspector}.go` | Local inspection dashboard, REST API, request capture |
| `internal/client/display.go` | Bubble Tea TUI |
| `internal/protocol/protocol.go` | Shared message types, JSON control + binary data frames |
| `internal/auth/users.go` | Flat-file user store, hashed-lookup token check, rate limiter |
| `internal/config/config.go` | `mabo-tunnel.yml` loader |
| `internal/secrets/secrets.go` | AES-256-GCM + XOR-split key helpers for embedded AIO config |
| `internal/version/version.go` | Build version, single source |

## Request lifecycle (HTTP)

1. Client dials `ws(s)://server/tunnel/connect`, sends an `auth_request`.
2. Server validates the token (constant-time), assigns a subdomain, replies
   with `auth_response` (tunnel URL, username, protocol).
3. A public request hits `abc123.tunnel.example.com`. The server:
   - extracts the subdomain, looks up the tunnel,
   - applies IP allow/deny and Basic-Auth checks,
   - rejects bodies over 10 MiB (`413` + a `notice` to the owner),
   - dumps the raw HTTP request and sends it as a `data` frame keyed by a new `conn_id`.
4. Client parses the request, forwards it to the local app, and streams the
   response back as `resp_header` → `resp_body*` → `resp_end`.
5. Server writes status/headers to the public caller as soon as `resp_header`
   arrives, then flushes each `resp_body` chunk — so SSE/LLM streams are live.
6. If the public caller disconnects mid-stream, the server sends a `close`
   frame with `reason=cancel`; the client aborts the upstream request.

See [protocol.md](protocol.md) for the wire format.

## Concurrency model

**Server** (per tunnel):
- one read loop consuming client frames,
- one ping loop (25s),
- one goroutine per in-flight public request streaming the response,
- writes to the WebSocket are serialized by `tunnel.writeMu`,
- in-flight requests tracked in `tunnel.pending` (`conn_id → *ProxiedConn`),
  each backed by a 512-slot buffered event channel; a slow public consumer
  that fills the buffer gets its connection torn down rather than blocking the
  shared read loop.

**Client**:
- a worker pool of 100 goroutines drains a 500-deep request queue; when full,
  new requests get a synthetic `503 Client overloaded`,
- a shared `http.Client` with connection pooling and forced HTTP/2 attempt,
- per-request `context` stored in `reqCancels` so server cancels propagate,
- its own 10s ping loop to measure RTT (shown in the TUI).

## Reconnection & session persistence

- The client generates a random `session_id` at startup and re-sends it on
  every reconnect.
- On a **non-graceful** disconnect the server reserves the subdomain for that
  `session_id` for 5 minutes, so the client reclaims the same URL on reconnect.
- On a **graceful** close (Ctrl+C sends a `close` with `reason=graceful`) the
  subdomain is released immediately.
- Backoff: 1s initial, ×2, capped at 60s, unlimited retries.

---

**More:** [architecture](architecture.md) · [protocol](protocol.md) ·
[server](server.md) · [client](client.md) · [deployment](deployment.md) ·
[security](security.md) · [development](development.md) · [FAQ](faq.md) ·
[troubleshooting](troubleshooting.md)
