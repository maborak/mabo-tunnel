# Protocol

The tunnel protocol runs over a single WebSocket connection established by the
client at `/tunnel/connect`. Control messages are **JSON envelopes** sent as
WebSocket text messages; bulk payloads are **binary frames** sent as WebSocket
binary messages. Multiple logical connections (public HTTP requests, TCP
connections, WS passthroughs) are multiplexed over the one WebSocket and
demultiplexed by `conn_id`.

- **Protocol version:** `1` (`protocol.Version`)
- **Transport:** WebSocket (upgraded from HTTP), `permessage-deflate` enabled
- **Encoding:** JSON for control, binary frames for payloads
- **Max frame:** 16 MiB (read limit on both ends)

## Binary frames

`encoding/json` serializes a `[]byte` field as base64. Carrying every proxied
byte that way costs a third more on the wire, plus an encode and a decode pass
on each end for every chunk. Payload-bearing messages therefore use a binary
frame instead:

```
byte  0      protocol version (protocol.BinaryVersion, currently 1)
byte  1      frame type (see below)
byte  2      conn ID length, in bytes
bytes 3..n   conn ID
bytes n..    payload
```

The payload length is implicit — one logical frame per WebSocket message. There
is no tunnel ID: the tunnel is the connection the frame arrived on.

| Constant | Value | Carries |
|----------|-------|---------|
| `BinTypeData` | 1 | Request head (S→C), WebSocket passthrough bytes (both ways) |
| `BinTypeRespBody` | 2 | Response body chunk (C→S) |
| `BinTypeTCPData` | 3 | Raw TCP bytes (both ways) |
| `BinTypeReqBody` | 4 | Request body chunk (S→C) |
| `BinTypeReqEnd` | 5 | End of request body (S→C), empty payload |

### Negotiation

Binary framing is opt-in per connection. The client sets `binary: true` in its
`auth_request`; the server echoes `binary: true` in `auth_response` if it
understands binary frames. Both sides send binary only after that exchange, so
an older client or an older server keeps working on the JSON path — the
equivalent JSON message types (`data`, `resp_body`, `tcp_data`, `req_body`,
`req_end`) remain accepted on both ends.

## Request and response streaming

Neither direction is buffered whole.

A request arrives as a `data` frame carrying only the head (request line and
headers), followed by `req_body` frames and a terminating `req_end`. The client
reassembles it into an outgoing request whose body reads from the incoming
frames, so a large upload starts reaching the local server while it is still
arriving at the edge.

A response goes back as one `resp_header` frame (status and headers), then
`resp_body` frames, then `resp_end`. The server writes and flushes each chunk as
it arrives, which is what lets SSE and other long-lived streams pass through.

If the server's per-request event buffer overflows — by event count **or by
buffered bytes** — the response is aborted rather than ended cleanly: the public
caller sees a broken transfer instead of a truncated body under a `200 OK`.

## Frame payload limits

Both peers enforce per-type payload limits on frames they receive. The queues
draining these frames are sized for the chunk sizes below; a frame that
massively exceeds its limit would pin orders of magnitude more memory per queue
slot than the design accounts for, so the receiver treats it as a protocol
violation and **tears down the tunnel connection**.

| Limit | Value | Applies to |
|-------|-------|------------|
| `MaxStreamChunkBytes` | 64 KiB | `resp_body`, `req_body`, `tcp_data` payloads |
| `MaxDataFrameBytes` | 8 MiB | `data` payloads client → server (WS-passthrough chunks; legacy whole-response path) |
| `MaxRequestHeadBytes` | 2 MiB | `data` payloads server → client (the request head) |

Peers in this project send well under these limits: request bodies chunk at
32 KiB, responses at 16 KiB, WS-passthrough reads at 32 KiB, and a forwarded
request head is bounded by net/http's 1 MiB header limit.

## Header hygiene

Hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-Authenticate`,
`Proxy-Authorization`, `Te`, `Trailer`, `Transfer-Encoding`, `Upgrade`) are
removed from proxied messages in both directions — the set lives once in
`protocol.HopByHopHeaders`. On the response path the server additionally drops
anything the peer's own `Connection` header names, and the peer's asserted
`Content-Length`: the framing of the public response is computed from the body
bytes actually forwarded, not from a length a tunnel peer declares.

## Envelope

Every message is wrapped:

```json
{
  "type": "data",
  "version": 1,
  "payload": { }
}
```

| Field | Notes |
|-------|-------|
| `type` | message-type discriminator (see below) |
| `version` | protocol version, omitted when zero |
| `payload` | type-specific object; omitted for ping/pong |

## Message types

| Type | Direction | Payload | Purpose |
|------|-----------|---------|---------|
| `auth_request` | client → server | `AuthRequest` | Authenticate, request subdomain/protocol |
| `auth_response` | server → client | `AuthResponse` | Auth result, assigned URL |
| `data` | bidirectional | `DataFrame` | Raw HTTP request (S→C) and WebSocket-passthrough bytes (both ways) |
| `resp_header` | client → server | `RespHeaderFrame` | First frame of a streaming HTTP response (status + headers) |
| `resp_body` | client → server | `DataFrame` | A chunk of streaming HTTP response body |
| `resp_end` | client → server | `CloseFrame` | End of a streaming HTTP response (empty reason = clean EOF) |
| `tcp_data` | bidirectional | `DataFrame` | Raw bytes for a TCP tunnel connection |
| `close` | bidirectional | `CloseFrame` | Close/cancel a logical connection |
| `notice` | server → client | `Notice` | Out-of-band warning (e.g. oversize upload) |
| `ping` / `pong` | bidirectional | — | Application-level keepalive (WebSocket-level ping/pong also used) |
| `tunnel_request` / `tunnel_response` | — | `TunnelRequest`/`TunnelResponse` | Defined in the protocol but not used by the current single-tunnel-per-connection flow |

> **Note on `data` vs `resp_*`:** HTTP responses now stream via
> `resp_header`/`resp_body`/`resp_end`. `data` carries the inbound HTTP request
> and WebSocket-passthrough bytes. The server keeps a legacy path that accepts
> a full HTTP response inside a single `data` frame for older clients, logging a
> warning when it fires.

## Payloads

### AuthRequest

```go
Token      string   // required
Subdomain  string   // request a specific subdomain (single tunnel only)
SessionID  string   // stable across reconnects; drives subdomain reservation
Name       string   // named tunnel → subdomain "username-name"
Graceful   bool     // set on clean shutdown
Protocol   string   // "http" (default) or "tcp"
AllowedIPs []string // IP allow list — enforced by server, NOT set by the bundled CLI
DeniedIPs  []string // IP deny list  — enforced by server, NOT set by the bundled CLI
BasicAuth  string   // "user:pass" — HTTP Basic Auth on the tunnel
```

> `AllowedIPs` / `DeniedIPs` are honored by the server
> (`http_proxy.go:checkIPAccess`) but the shipped client never populates them —
> there is no CLI flag or YAML key. To use IP filtering today you would send a
> custom `auth_request`. Wiring a `--allow` / `--deny` flag is on the roadmap.

### AuthResponse

```go
Success   bool
Message   string
TunnelID  string
Subdomain string
URL       string   // e.g. https://abc123.tunnel.example.com or tcp://host:10001
Username  string
Protocol  string   // "http" or "tcp"
TCPPort   int      // assigned port, TCP tunnels only
```

### DataFrame

```go
ConnID   string   // logical connection id (per public request / TCP conn)
TunnelID string
Data     []byte   // raw bytes (base64 in JSON)
```

### RespHeaderFrame

```go
ConnID     string
TunnelID   string
StatusCode int                 // "status"
Headers    map[string][]string
```

### CloseFrame

```go
ConnID   string
TunnelID string
Reason   string   // "" clean; "cancel"; "tcp_eof"; "graceful"; or an error string
```

Reason constants: `cancel` (public caller went away — abort upstream),
`tcp_eof` (the local TCP or WebSocket-passthrough peer finished; on receipt the
server closes the matching public side), `graceful` (client Ctrl+C).

### Notice

```go
Level   string   // "warn" | "error" | "info"
Code    string   // e.g. "body_too_large"
Message string
Method  string
Path    string
Size    int64
Limit   int64
```

Currently the only code is `body_too_large`, surfaced in the client TUI when an
upload is rejected at the edge.

## Handshake

```
client                         server
  │  ws connect /tunnel/connect  │
  │─────────────────────────────▶│  (upgrade; 10s auth deadline)
  │  auth_request {token,...}     │
  │─────────────────────────────▶│  validate token (constant-time)
  │                               │  assign subdomain / TCP port
  │  auth_response {url,...}       │
  │◀─────────────────────────────│
  │  ── ping/pong keepalive ──    │
```

Auth failures are rate-limited to 5 attempts per minute per source IP. The
first message must be an `auth_request`; anything else is rejected.

## Keepalive

- **Server → client:** WebSocket ping every 25s; connection considered dead if
  no pong within 90s (`pongWait`). The pong handler resets the read deadline
  and updates last-activity.
- **Client → server:** WebSocket ping every 10s, used to measure round-trip
  latency shown in the TUI.
- Idle tunnels (no activity for 5 minutes) are evicted by a 30s cleanup loop.

## Limits

| Limit | Value |
|-------|-------|
| WebSocket frame read limit | 16 MiB (both ends) |
| Per-frame payload limits | see [Frame payload limits](#frame-payload-limits) above |
| HTTP request body | 10 MiB (server) |
| Response first-header timeout | 60s |
| In-flight requests per tunnel | 200, including WebSocket passthrough (server) |
| Proxied-response event buffer | 512 events **and** 8 MiB body bytes per in-flight request (server); overflow aborts the response |
| WS-passthrough data channel | 256 chunks **and** 8 MiB per passthrough connection (server); overflow closes the connection |

---

**More:** [architecture](architecture.md) · [protocol](protocol.md) ·
[server](server.md) · [client](client.md) · [deployment](deployment.md) ·
[security](security.md) · [development](development.md) · [FAQ](faq.md) ·
[troubleshooting](troubleshooting.md)
