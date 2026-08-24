# Troubleshooting

Symptom → cause → fix. Every error string below is one Mabo Tunnel actually emits,
so you can search this page for what you see on screen.

Turn on detail before diagnosing anything:

```bash
mabo-tunnel-server --log-level=debug     # per-request logging and source locations
```

> [!WARNING]
> `debug` is also the level most likely to put sensitive material in a log you
> then paste somewhere. Check the output before sharing it.

---

## The client will not connect

### `Error: --token is required`

No token was given and `MABO_TUNNEL_TOKEN` is unset. Generate one on the **server**:

```bash
mabo-tunnel-token generate alice pro >> data/users.txt
```

The token is printed once, to stderr, and cannot be recovered afterwards.

### The connection is refused, or hangs

Check what the client is actually dialling. With no `--server` and no
`MABO_TUNNEL_SERVER`, it dials `ws://localhost:8080` — a binary built from this
repository never defaults to a remote host.

```bash
mabo-tunnel-client --server=wss://tunnel.example.com --token=$TOKEN --port=3000
```

Then, in order:

1. Is the server running and reachable? `curl -sS https://tunnel.example.com/health`
2. Scheme mismatch: `ws://` to a TLS-terminated server, or `wss://` to a plain
   one, both fail. Use `wss://` whenever the URL is `https://`.
3. A reverse proxy in front that does not forward the `Upgrade` and `Connection`
   headers will break the WebSocket handshake. See
   [`deployment.md`](deployment.md).

### Auth fails with a valid-looking token

The server compares `sha256(token)` against `data/users.txt`. Common causes:

- **The file was edited after the server started.** It is read at startup only;
  restart the server.
- **Whitespace.** A trailing space or a CR from a Windows editor changes the
  hash. Lines are `sha256:<hex>:username:plan`, nothing else.
- **The token was rotated** but the old one is still in your shell history or
  `.env`.
- **A legacy plaintext file** loads with a startup warning. Those lines are live
  credentials — convert them with `mabo-tunnel-token migrate data/users.txt`.

Confirm a token hashes to the line you expect:

```bash
printf '%s' "$TOKEN" | shasum -a 256
```

### `quota exceeded: 1/1 tunnels for plan "free"`

`free` allows 1 concurrent tunnel, `pro` allows 10. A crashed client can leave a
tunnel registered until it is evicted — the server drops an idle tunnel after
5 minutes. Wait, or reconnect and reuse the session.

---

## The tunnel is up but requests fail

### `No tunnel specified. Use <subdomain>.example.com`

The request arrived at the base domain with no subdomain. Requests must go to
`<subdomain>.tunnel.example.com`, not `tunnel.example.com`.

### `Tunnel "abc123" not found. It may have been closed.`

The subdomain does not map to a live tunnel. Either the client disconnected, or
the request went to a stale URL. Subdomains are held for 5 minutes after a
disconnect so a reconnect keeps its URL; after that the name is released.

For a local setup, also check that `*.localhost` resolves on your machine — it
does on most Linux and macOS systems, but not all. Fall back to `curl` with an
explicit `Host` header:

```bash
curl -H 'Host: abc123.localhost' http://127.0.0.1:8080/
```

### `502 Tunnel communication error` / `502 Tunnel closed during request`

The client vanished mid-request — killed, network dropped, or the machine slept.
The client reconnects with backoff; the in-flight request cannot be recovered.

### `504 Upstream timeout (no response headers within 60s)`

Your **local** service did not send response headers within 60 seconds. The
tunnel is fine; the application behind it is slow or wedged. Note the bound is
on the *first byte* — once headers arrive, the body streams with no overall
deadline, so long downloads and infinite SSE streams are fine.

### `503 Tunnel is at its concurrent request limit`

One tunnel may have 200 requests in flight. Either the client machine cannot
keep up, or something is opening connections and never reading them. The server
logs a `tunnel at in-flight request limit` warning with the tunnel ID.

### `503 Client overloaded`

Different limit, other end: the client's own request queue (500 deep, drained by
100 workers) filled up. Your local service is the bottleneck.

### `413 Request body exceeds 10485760 bytes (tunnel limit)`

Request bodies are capped at 10 MiB. Known-length uploads are rejected up front;
chunked ones are cut off mid-stream. The tunnel owner also gets a
`body_too_large` notice in the TUI. The limit is a compile-time constant
(`maxRequestBodySize` in `internal/server/http_proxy.go`).

### `403 Forbidden: your IP is not allowed to access this tunnel`

The tunnel has an IP allow/deny list and your address is not permitted. Note the
server decides your address via `--trusted-proxies`: if the server sits behind a
proxy that is **not** in that list, every request looks like it came from the
proxy. See below.

### `401 Unauthorized`

The tunnel has HTTP Basic Auth (`--auth user:pass`). Supply credentials.

---

## Everything looks like it comes from one IP

Logs and IP rules show the reverse proxy's address instead of the real client.

`X-Forwarded-For` is believed **only** when the request arrives from a CIDR in
`--trusted-proxies` (default: loopback and private ranges). Behind a proxy on a
public address, set it explicitly:

```bash
mabo-tunnel-server --trusted-proxies=203.0.113.10/32,10.0.0.0/8
```

This is deliberately fail-closed: trusting the header from an untrusted peer
would let anyone spoof their address and walk straight past a tunnel's IP
allowlist.

---

## TLS and certificates

### AIO mode never gets a certificate

Wildcard certificates require the DNS-01 challenge, so the Cloudflare token has
to be able to write DNS records:

1. Token permissions are `Zone > DNS > Edit` **on the zone you tunnel under**.
2. `--domain` matches that zone.
3. The host can reach the Let's Encrypt and Cloudflare APIs outbound.
4. `--aio-email` is set — AIO refuses to start without it.

Watch it happen with `--log-level=debug`. Certificates are cached under
`--aio-cert-path` (default `data/certs`); a wrong path means re-issuing on every
restart, which will hit Let's Encrypt's rate limits.

### Browser warns about the certificate on a subdomain

The wildcard covers exactly one level: `*.tunnel.example.com` matches
`abc.tunnel.example.com`, not `a.b.tunnel.example.com`. Tunnel names containing
a dot will not match.

---

## Streaming and WebSockets

### SSE or streamed responses arrive all at once

Mabo Tunnel streams chunk by chunk and does not buffer. If output is arriving in one
lump, the buffering is elsewhere:

- A reverse proxy in front with response buffering enabled (nginx
  `proxy_buffering on` is the usual culprit; Caddy does not buffer by default).
- The local application itself not flushing.
- A client library that waits for the whole body.

Verify by hitting the local service directly and comparing.

### The proxied app's own WebSocket does not connect

That path is supported end to end. Check that nothing between the internet and
the Mabo Tunnel server strips `Upgrade`/`Connection`, and that the app's URL uses
`wss://` when the tunnel is HTTPS.

---

## Dashboard

### The dashboard URL will not open from another machine

By design — it binds to loopback and rejects non-local requests. Use an SSH
tunnel:

```bash
ssh -L 4040:localhost:<dashboard-port> your-machine
```

### A body shows as truncated

Captures are bounded: 100 requests per tunnel in a ring buffer, 64 KiB per body.
Older requests are evicted as new ones arrive.

---

## Build and test

### `go install` cannot find the module

The import path is `github.com/maborak/mabo-tunnel`. If `go install` 404s, the
module path and the repository location disagree — build from source instead:

```bash
git clone https://github.com/maborak/mabo-tunnel && cd mabo-tunnel && make build
```

### Tests hang or fail only on CI

The suite is fully in-process — no network, no fixed ports. A hang usually means
a goroutine waiting on a channel nobody closes. Run with the race detector and a
timeout:

```bash
go test -race -timeout 120s ./...
```

### `gofmt -l .` prints files you did not touch

Your editor is reformatting on save with different settings. Run `gofmt -w` on
just your files, and check nothing else is in the diff before committing.

---

## Still stuck

- [`architecture.md`](architecture.md) — what runs where, and the concurrency model
- [`protocol.md`](protocol.md) — the wire format, if you are debugging frames
- [`security.md`](security.md) — the auth model and what is intentional
- [Discussions](https://github.com/maborak/mabo-tunnel/discussions) for questions
- [Issues](https://github.com/maborak/mabo-tunnel/issues) for reproducible bugs —
  but read [`SECURITY.md`](../SECURITY.md) first if it is a security problem

---

**More:** [architecture](architecture.md) · [protocol](protocol.md) ·
[server](server.md) · [client](client.md) · [deployment](deployment.md) ·
[security](security.md) · [development](development.md) · [FAQ](faq.md) ·
[troubleshooting](troubleshooting.md)
