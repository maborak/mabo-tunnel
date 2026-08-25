# Server

The server accepts public traffic and forwards it to connected clients. It runs
in one of two modes:

- **Plain** — HTTP only, meant to sit behind a TLS-terminating reverse proxy
  (Caddy/nginx). This is the default.
- **All-in-one (AIO)** — binds `:80` and `:443` directly and auto-provisions
  Let's Encrypt **wildcard** certificates via the Cloudflare DNS-01 challenge.
  No reverse proxy needed.

## Flags

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--addr` | `MABO_TUNNEL_ADDR` | `:8080` | HTTP listen address (plain mode) |
| `--domain` | `MABO_TUNNEL_DOMAIN` | `localhost` | Base domain for tunnels |
| `--users-file` | `MABO_TUNNEL_USERS_FILE` | `data/users.txt` | Path to the user store |
| `--log-level` | `MABO_TUNNEL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. `debug` also turns on source locations and per-request logging |
| `--trusted-proxies` | `MABO_TUNNEL_TRUSTED_PROXIES` | loopback + private ranges | Comma-separated CIDRs whose `X-Forwarded-For` header is believed |
| `--tcp-port-min` | `MABO_TUNNEL_TCP_PORT_MIN` | `10000` | Start of the TCP tunnel port range |
| `--tcp-port-max` | `MABO_TUNNEL_TCP_PORT_MAX` | `10100` | End of the TCP tunnel port range |
| `--aio` | — | `false` | All-in-one mode: HTTP `:80` + HTTPS `:443` + auto certs |
| `--aio-bind` | `MABO_TUNNEL_AIO_BIND` | `0.0.0.0` | Bind IP in AIO mode |
| `--aio-email` | `MABO_TUNNEL_AIO_EMAIL` | — | ACME email (required in AIO) |
| `--aio-cf-token` | `CF_API_TOKEN` | — | Cloudflare API token for DNS-01 (required in AIO) |
| `--aio-cert-path` | `MABO_TUNNEL_AIO_CERT_PATH` | `data/certs` | Certificate storage directory |
| `--version` | — | — | Print version and exit |
| `--upgrade` | — | — | Self-update this binary from GitHub Releases, then exit |
| `--force-upgrade` | — | — | With `--upgrade`: reinstall even if already up to date |

Precedence: **CLI flag → environment variable → built-in default**. In hardened
AIO builds, encrypted embedded values fill in as a further fallback (see
[security.md](security.md)).

Self-update mechanics are shared with the client and documented in
[client.md](client.md#self-updating). Two server-specific caveats:

- **AIO builds refuse `--upgrade`.** A hardened AIO binary carries encrypted
  embedded config (domain, users, certs); a stock release binary does not, so
  upgrading would silently de-harden the deployment at next restart. Re-run the
  embed-secrets flow instead, or pass `--force-upgrade` to accept.
- **Docker deployments must not self-update** — rebuild the image instead (see
  [deployment.md](deployment.md)).

## Running

### Plain (behind Caddy/nginx)

```bash
./build/mabo-tunnel-server \
  --addr=:8080 \
  --domain=tunnel.example.com \
  --users-file=data/users.txt
```

The reverse proxy terminates TLS and forwards to `:8080`. It **must** pass
`X-Forwarded-For` (used for IP filtering and rate limiting) and forward
WebSocket upgrades. See [deployment.md](deployment.md) for a Caddy config.

`X-Forwarded-For` is caller-supplied data, so it is only honored when the
request reached the server from a trusted hop. The default trusted set is
loopback plus the RFC1918 private ranges, which covers a reverse proxy on the
same host or in the same container network — the usual deployment. If your proxy
sits on a public address, name it explicitly:

```bash
--trusted-proxies=203.0.113.10/32
```

Without that the server falls back to the peer address, and a tunnel's IP allow
list will see the proxy rather than the real caller. With no trusted hop
configured and a request arriving directly from the internet, the header is
ignored entirely — otherwise any caller could name itself and walk straight
through an allow list.

Before a request head is forwarded through the tunnel, the server appends the
origin it verified to `X-Forwarded-For` — standard proxy semantics where each
hop appends the address it received the request from. An app behind the tunnel
that reads the **rightmost** entry gets an address this server chose, not one
the caller typed; entries to its left may still be caller-supplied. Deny-list
entries are compared on canonical IP forms, so `::ffff:6.6.6.6` matches a
`6.6.6.6` deny entry.

### All-in-one

```bash
./build/mabo-tunnel-server --aio \
  --domain=tunnel.example.com \
  --aio-email=admin@example.com \
  --aio-cf-token=YOUR_CLOUDFLARE_TOKEN \
  --aio-bind=0.0.0.0
```

On start, the server provisions certs for `tunnel.example.com` and
`*.tunnel.example.com`, then serves HTTP on `:80` and HTTPS on `:443`.
Requires a Cloudflare-managed zone and a token with DNS edit rights.

## Routing

`ServeHTTP` dispatches by Host:

- `*.{domain}` → the tunnel proxy (subdomain lookup, then relay).
- Everything else → the built-in mux (`/tunnel/connect`, health endpoints, root).

Subdomain extraction rejects nested labels (`a.b.{domain}` is not a valid
tunnel host).

## Endpoints

| Path | Purpose | Response |
|------|---------|----------|
| `/tunnel/connect` | WebSocket endpoint for clients | upgrade |
| `/health` | Liveness | `{"status":"ok"}` |
| `/ready` | Readiness | `200 {"status":"ready","active_tunnels":N,"users_loaded":N}` or `503 {"status":"not_ready","reason":"no_users_loaded"}` |
| `/` | Service info | `{"service":"mabo-tunnel","version":"...","domain":...,"active_tunnels":N}` |

`/ready` returns `503` while zero users are loaded — wire it into your
orchestrator's readiness probe. `/health` is used by the Docker healthcheck.

The reported version comes from `internal/version`, stamped at build time by the
Makefile and Dockerfile (`-X .../internal/version.Version=...`). An unstamped
`go build` reports the package default.

## Users

The store is a flat file, one user per line. Tokens are stored **hashed**:

```
# sha256:<hex>:username:plan
sha256:c6e10d0dc8b822097c87ad06e68bd90cb71dcef5f8f54a9034ab6aeb35999afc:demo:free
sha256:ad8eaa5db7a40c8896ca3cb43458831e5b0be356d1fd941407339cabdb396834:admin:pro
```

The server only ever verifies a token a client presents; it never needs to
reproduce one. Storing `SHA-256(token)` means this file — and any binary that
embeds it — is not a list of working credentials. Tokens are 256 bits of
randomness, so a plain hash is sufficient; the slow KDFs (bcrypt, argon2) exist
for low-entropy human passwords and buy nothing here.

Manage users with `mabo-tunnel-token` (`make build-token`):

```bash
# New user. The token is printed once, to stderr — record it now.
mabo-tunnel-token generate alice pro >> data/users.txt

# Hash of an existing token, for hand-editing.
mabo-tunnel-token hash <token>

# Convert a legacy plaintext file in place.
mabo-tunnel-token migrate data/users.txt
```

- Lines starting with `#` and blank lines are ignored.
- `plan` must be `free` or `pro`; anything else fails to load.
- Lookup is a single map lookup on the hash — constant work regardless of how
  many users are loaded.
- Legacy `token:username:plan` lines still load, so nothing breaks on upgrade,
  but the server logs a warning naming how many are unhashed. Those lines are
  live credentials; migrate them.

> A token cannot be recovered once hashed. If a user loses theirs, generate a
> new one and replace the line.

Plan quotas (max concurrent tunnels per user) live in
`internal/server/tunnel.go` (`PlanLimits`): `free` = 1, `pro` = 10.

> The file is read at startup (or decrypted from the embedded blob in AIO
> builds). There is no live-reload endpoint; restart to pick up changes.

## TCP tunnels

When a client connects with `--protocol=tcp`, the server allocates a port from
`[--tcp-port-min, --tcp-port-max]`, listens on it, and relays raw bytes both
ways over the WebSocket. The public endpoint is `tcp://{domain}:{port}`. Make
sure that port range is open in your firewall / security group.

## Shutdown

`SIGINT`/`SIGTERM` cancels the run context: the server drains all tunnels
(sends WebSocket close frames), stops the cleanup loop, and shuts the HTTP
server(s) down with a 10s grace period.

---

**More:** [architecture](architecture.md) · [protocol](protocol.md) ·
[server](server.md) · [client](client.md) · [deployment](deployment.md) ·
[security](security.md) · [development](development.md) · [FAQ](faq.md) ·
[troubleshooting](troubleshooting.md)
