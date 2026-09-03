<div align="center">

# Mabo Tunnel

**Your own tunnel server, on your own domain.** Expose local servers to the
internet through secure tunnels. Single binary, no dependencies, no database.

[![CI](https://github.com/maborak/mabo-tunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/maborak/mabo-tunnel/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/maborak/mabo-tunnel.svg)](https://pkg.go.dev/github.com/maborak/mabo-tunnel)
[![Go Report Card](https://goreportcard.com/badge/github.com/maborak/mabo-tunnel)](https://goreportcard.com/report/github.com/maborak/mabo-tunnel)
[![Latest release](https://img.shields.io/github/v/release/maborak/mabo-tunnel?sort=semver)](https://github.com/maborak/mabo-tunnel/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Quick start](#quick-start) · [Install](#install) · [Self-hosting](#self-hosting) ·
[Documentation](#documentation) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

</div>

---

```
Internet  ──HTTPS──▶  Mabo Tunnel Server  ──WebSocket──▶  Mabo Tunnel Client  ──▶  localhost:3000
                      (your VPS)                       (your machine)        (your app)
```

You run both halves. There is no third party in the path, no account to sign up
for, and no request limit other than the ones you configure.

## Why

Existing tunnel services are excellent, and they are also someone else's server
holding your traffic, with a seat price and a request cap. Mabo Tunnel is the same
shape of tool for people who already have a VPS and a domain:

- **You own the endpoint.** Your domain, your certificate, your logs.
- **One binary per side.** No runtime, no database, no config server. The user
  store is a text file.
- **It streams.** SSE, chunked responses, and LLM token streams pass through
  chunk by chunk instead of being buffered, so a proxied stream behaves like a
  direct one.
- **It stays small.** One Go module, a handful of dependencies, ~10k lines.

## Features

- **HTTP & TCP tunnels** — many logical connections multiplexed over a single
  WebSocket
- **Streaming both ways** — SSE, chunked, LLM token streams; large uploads start
  reaching your service before they finish arriving
- **WebSocket passthrough** — proxied apps serve their own WebSockets end to end
- **Multi-port** — expose several services in one command
- **Remote host forwarding** — tunnel to any reachable host, not just localhost
- **Named tunnels** — stable subdomains (`user_api.tunnel.example.com`)
- **Auto-reconnect** — exponential backoff with jitter; the same subdomain is
  held for 5 minutes so a reconnect keeps its URL
- **Web dashboard** — request inspector with replay, body viewer, filters, and
  copy-as cURL / fetch / wget
- **TUI** — colour-coded request log, both HTTP and HTTPS URLs, ping latency
- **All-in-one mode** — built-in TLS with automatic Let's Encrypt wildcard
  certificates. No Caddy or nginx required
- **HTTP Basic Auth** per tunnel, and header add/remove rules
- **IP allow/deny lists** per tunnel — `--allow-ip` / `--deny-ip`, matched as
  real CIDR networks at the edge
- **Custom domains** — users can point their own hostnames at a tunnel,
  verified via a TXT challenge, with on-demand certificates in AIO mode
- **Admin API & metrics** — token-guarded endpoints to list/revoke tunnels and
  reload users live, plus a Prometheus `/metrics` endpoint
- **Rate limiting** — optional per-tunnel request-rate cap (`--tunnel-rps`)
- **Hot user management** — the users file reloads on change or `SIGHUP`; no
  restart to add or revoke a user
- **Configurable plans** — quota overrides per user in the users file, plus
  server-side plan defaults
- **HAR export** — captured traffic downloads as HAR 1.2 for devtools; WS
  passthrough sessions are inspected chunk-by-chunk
- **Hashed tokens** — the user store keeps only `SHA-256(token)`, so it is not a
  credential list
- **YAML config** for the client
- **Cross-platform** — Linux (amd64/arm64), macOS (Intel/Apple Silicon), Windows

## Install

### Download a release

Grab a binary for your platform from the
[latest release](https://github.com/maborak/mabo-tunnel/releases/latest), then verify
it:

```bash
sha256sum -c --ignore-missing SHA256SUMS.txt
```

```bash
# Linux amd64, for example
curl -sSLO https://github.com/maborak/mabo-tunnel/releases/latest/download/mabo-tunnel-client-linux-amd64
chmod +x mabo-tunnel-client-linux-amd64
sudo mv mabo-tunnel-client-linux-amd64 /usr/local/bin/mabo-tunnel-client
```

### With Go

```bash
go install github.com/maborak/mabo-tunnel/cmd/client@latest        # mabo-tunnel client
go install github.com/maborak/mabo-tunnel/cmd/server@latest        # mabo-tunnel server
go install github.com/maborak/mabo-tunnel/cmd/token@latest # token management
```

### From source

```bash
git clone https://github.com/maborak/mabo-tunnel
cd mabo-tunnel
make build      # → build/mabo-tunnel-server, build/mabo-tunnel-client, build/mabo-tunnel-token
```

Requires Go 1.26+; `go.mod` targets 1.26.6 and `GOTOOLCHAIN=auto` will fetch it.

### Updating an installed binary

Release binaries can update themselves:

```bash
mabo-tunnel-client --upgrade   # same for mabo-tunnel-server
```

This fetches the latest release, verifies the download against the release's
`SHA256SUMS.txt`, and atomically replaces the binary in place — restart to run
the new version. See [docs/client.md](docs/client.md#self-updating) for
caveats (Docker, Homebrew, rate limits).

> [!IMPORTANT]
> Binaries built from this repository default to a **local** server
> (`ws://localhost:8080`) and a **local** domain (`localhost`). They will never
> silently talk to someone else's infrastructure. Point them at your own
> deployment with `--server` / `--domain`, the matching environment variables,
> or `-ldflags` at build time.

## Quick start

Everything on one machine, in three terminals — no domain or TLS needed.

```bash
# 1. Build and create a user
make build
./build/mabo-tunnel-token generate demo free >> data/users.txt   # token printed once, to stderr

# 2. Start the server
./build/mabo-tunnel-server --domain=localhost --addr=:8080

# 3. Start something to expose, then tunnel it
python3 -m http.server 3000
./build/mabo-tunnel-client --server=ws://localhost:8080 --token=<TOKEN> --port=3000
```

The client prints your tunnel URL and a dashboard URL. Open the tunnel URL and
watch the request appear in the dashboard.

## Self-hosting

You need a VPS and a domain with a **wildcard DNS record** pointing at it:

```
tunnel.example.com.    A    203.0.113.10
*.tunnel.example.com.  A    203.0.113.10
```

Then pick one of two deployments.

### All-in-one — one binary, built-in TLS

The server terminates TLS itself on `:80`/`:443` and provisions Let's Encrypt
wildcard certificates over the Cloudflare DNS-01 challenge.

```bash
./mabo-tunnel-server --aio \
  --domain=tunnel.example.com \
  --aio-email=admin@example.com \
  --aio-cf-token=$CF_API_TOKEN \
  --users-file=data/users.txt
```

Or bake it all into the binary so the host needs no configuration at all:

```bash
make build-aio AIO_DOMAIN=tunnel.example.com AIO_EMAIL=admin@example.com CF_API_TOKEN=xxx
scp build/mabo-tunnel-server server:/usr/local/bin/mabo-tunnel-server
ssh server /usr/local/bin/mabo-tunnel-server
```

> [!WARNING]
> An AIO binary embeds your Cloudflare token **encrypted with a key that ships
> in the same binary** — obfuscation, not encryption at rest. Anyone holding the
> binary can recover the token. Scope that token to one zone, or do not embed
> it. [`docs/security.md`](docs/security.md#caveat-this-is-obfuscation-not-encryption-at-rest)
> explains exactly what leaks and how to shrink it.

### Behind a reverse proxy

Run the server plain and let Caddy hold the certificate:

```bash
cp .env.example .env      # set CF_API_TOKEN and AIO_DOMAIN
docker compose up -d
```

Full walkthrough, including DNS and certificate setup:
[`docs/deployment.md`](docs/deployment.md).

### Managing users

`data/users.txt`, one user per line:

```
# sha256:<hex>:username:plan
sha256:c6e10d0dc8b822097c87ad06e68bd90cb71dcef5f8f54a9034ab6aeb35999afc:demo:free
sha256:ad8eaa5db7a40c8896ca3cb43458831e5b0be356d1fd941407339cabdb396834:admin:pro
```

Only the hash is stored, so this file is not a list of working credentials.

```bash
mabo-tunnel-token generate alice pro >> data/users.txt   # token printed once, to stderr
mabo-tunnel-token migrate data/users.txt                 # convert a legacy plaintext file
```

Plans: `free` (1 concurrent tunnel), `pro` (10). Add a fourth field to give one
user their own quota: `sha256:<hex>:alice:pro:25`. Plan defaults are
configurable with `--plan-free-tunnels` / `--plan-pro-tunnels`. The file is
watched and reloaded on change — also on `SIGHUP` or via the admin API — so
adding or revoking a user needs no restart.

## Using the client

```bash
# Single port
mabo-tunnel-client --token=$TOKEN --port=3000

# Named tunnels, multiple ports
mabo-tunnel-client --token=$TOKEN --port=ui:5173,api:9001

# Forward to another host on your network
mabo-tunnel-client --token=$TOKEN --port=ui:192.168.0.40:5173

# Protect the public endpoint
mabo-tunnel-client --token=$TOKEN --port=3000 --auth=admin:secret

# Only your office network can reach it
mabo-tunnel-client --token=$TOKEN --port=3000 --allow-ip=203.0.113.0/24

# Your own hostname (needs server --custom-domains plus a TXT ownership record)
mabo-tunnel-client --token=$TOKEN --port=3000 --custom-domain=demo.apps.example.com

# Ask for a specific subdomain
mabo-tunnel-client --token=$TOKEN --port=3000 --subdomain=myapp

# TCP tunnel, e.g. PostgreSQL
mabo-tunnel-client --token=$TOKEN --port=5432 --protocol=tcp
```

Port formats:

```
--port=3000                          # localhost:3000
--port=api:9001                      # named, localhost:9001
--port=ui:192.168.0.40:5173          # named, remote host
--port=ui:5173,api:9001              # multiple tunnels
--port=ui:192.168.0.40:5173,api:9001 # mixed
```

Or put it in `mabo-tunnel.yml` (see [`mabo-tunnel.yml.example`](mabo-tunnel.yml.example)):

```yaml
server: wss://tunnel.example.com
token: your-token-here

tunnels:
  frontend:
    port: 5173
    host: 192.168.0.40      # optional, default localhost
    auth: admin:secret      # optional, per-tunnel Basic Auth
    headers:
      add:
        X-Custom: value
      remove:
        - Cookie
  api:
    port: 9001
```

### Dashboard and TUI

The client serves a local dashboard (URL shown in the TUI) that inspects every
request and response: headers, bodies with JSON pretty-printing, filters by
method / status / path, replay, and copy-as cURL / fetch / wget. It binds to
loopback only.

The TUI shows both tunnel URLs, the dashboard URL, a colour-coded request log
per tunnel, and ping latency. Press `q` or `Ctrl+C` to quit.

## Configuration

### Server

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--addr` | `MABO_TUNNEL_ADDR` | `:8080` | HTTP listen address |
| `--domain` | `MABO_TUNNEL_DOMAIN` | `localhost` | Base domain for tunnels |
| `--users-file` | `MABO_TUNNEL_USERS_FILE` | `data/users.txt` | Path to users file |
| `--log-level` | `MABO_TUNNEL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `--trusted-proxies` | `MABO_TUNNEL_TRUSTED_PROXIES` | loopback + private | CIDRs whose `X-Forwarded-For` is believed |
| `--tcp-port-min` | `MABO_TUNNEL_TCP_PORT_MIN` | `10000` | TCP tunnel port range start |
| `--tcp-port-max` | `MABO_TUNNEL_TCP_PORT_MAX` | `10100` | TCP tunnel port range end |
| `--aio` | — | `false` | All-in-one mode (HTTP:80 + HTTPS:443 + auto certs) |
| `--aio-bind` | `MABO_TUNNEL_AIO_BIND` | `0.0.0.0` | Bind IP for AIO mode |
| `--aio-email` | `MABO_TUNNEL_AIO_EMAIL` | — | ACME email for Let's Encrypt |
| `--aio-cf-token` | `CF_API_TOKEN` | — | Cloudflare API token (DNS-01) |
| `--aio-cert-path` | `MABO_TUNNEL_AIO_CERT_PATH` | `data/certs` | Certificate storage directory |
| `--aio-dns-provider` | `MABO_TUNNEL_AIO_DNS_PROVIDER` | `cloudflare` | DNS-01 provider: `cloudflare`, `digitalocean`, `route53` |
| `--aio-dns-secret` | `MABO_TUNNEL_AIO_DNS_SECRET` | — | Second credential for the provider (AWS Secret Access Key) |
| `--admin-token` | `MABO_TUNNEL_ADMIN_TOKEN` | — | Enable `/admin/*` + `/metrics`, guarded by this bearer token |
| `--custom-domains` | `MABO_TUNNEL_CUSTOM_DOMAINS` | — | Zone suffixes users may register verified hostnames under |
| `--plan-free-tunnels` | `MABO_TUNNEL_PLAN_FREE_TUNNELS` | `1` | Free-plan concurrent tunnels (per-user override wins) |
| `--plan-pro-tunnels` | `MABO_TUNNEL_PLAN_PRO_TUNNELS` | `10` | Pro-plan concurrent tunnels (per-user override wins) |
| `--tunnel-rps` | `MABO_TUNNEL_TUNNEL_RPS` | off | Per-tunnel request-rate cap (req/s) |
| `--tunnel-burst` | `MABO_TUNNEL_TUNNEL_BURST` | =rps | Instant burst above the per-tunnel rate |

### Client

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--server` | `MABO_TUNNEL_SERVER` | `ws://localhost:8080` | Server WebSocket URL |
| `--token` | `MABO_TUNNEL_TOKEN` | (required) | Auth token |
| `--port` | — | (required) | Ports to expose (see formats above) |
| `--subdomain` | `MABO_TUNNEL_SUBDOMAIN` | (random) | Request a specific subdomain |
| `--protocol` | `MABO_TUNNEL_PROTOCOL` | `http` | Tunnel protocol: `http` or `tcp` |
| `--auth` | `MABO_TUNNEL_AUTH` | — | HTTP Basic Auth (`user:pass`) |
| `--config` | — | `mabo-tunnel.yml` | Path to YAML config file |
| `--header-add` | — | — | Add a header to proxied requests (repeatable) |
| `--header-remove` | — | — | Remove a header from proxied requests (repeatable) |
| `--allow-ip` | `MABO_TUNNEL_ALLOW_IPS` | — | CIDR/IP allowed to reach the tunnel (repeatable, comma-separated) |
| `--deny-ip` | `MABO_TUNNEL_DENY_IPS` | — | CIDR/IP blocked from the tunnel (checked before the allow list) |
| `--custom-domain` | `MABO_TUNNEL_CUSTOM_DOMAIN` | — | Serve the tunnel under a verified hostname (single port only) |

## Limits and timeouts

| Limit | Value | Where |
|-------|-------|-------|
| Max HTTP request body | 10 MiB | server rejects with `413`, notifies the tunnel owner |
| Max WebSocket frame | 16 MiB | server + client read limit |
| Time to first response header | 60s | after headers arrive the body streams with no overall deadline |
| Keepalive | server ping 25s / pong wait 90s; client ping 10s | WebSocket ping/pong |
| In-flight requests per tunnel | 200 | excess gets `503`, logged |
| Idle tunnel eviction | 5 min | subdomain reserved 5 min for reconnect |
| Auth rate limit | 5 failed attempts / min / IP | per source IP |
| Plan quotas | `free` 1, `pro` 10 (configurable; per-user override via users file) | `internal/server/tunnel.go` |
| Per-tunnel rate limit | off by default (`--tunnel-rps`) | `internal/server/ratelimit.go` |
| Custom domain | TXT `_mabo-challenge.<domain>` = sha256("<token-hash>.<domain>") | `--custom-domains` |
| TCP tunnel port range | 10000–10100 | configurable |
| Dashboard capture | 100 requests/tunnel, 64 KiB body cap | in-memory ring buffer |

## Documentation

| Doc | Contents |
|-----|----------|
| [architecture.md](docs/architecture.md) | Components, request lifecycle, concurrency model |
| [protocol.md](docs/protocol.md) | Wire format, message types, framing, limits |
| [server.md](docs/server.md) | Server flags, TLS/AIO, health endpoints |
| [client.md](docs/client.md) | Client flags, port formats, YAML, dashboard, TUI |
| [deployment.md](docs/deployment.md) | Docker + Caddy, AIO single-binary, DNS/TLS setup |
| [security.md](docs/security.md) | Auth model, limits, what the AIO build does and does not protect |
| [development.md](docs/development.md) | Build, test, project layout |
| [faq.md](docs/faq.md) | How it compares, what it is not, common questions |
| [troubleshooting.md](docs/troubleshooting.md) | Symptom → cause → fix |

## Development

```bash
make build          # server + client + token tool
make test           # go test ./...
make test-race      # go test -race ./...   — required for concurrency changes
make build-all      # cross-compile (no AIO)
make clean
```

Before opening a PR: `gofmt -l .` prints nothing, `go vet ./...` is clean, and
`make test-race` passes. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Project status

Young but already used in production by its authors. Pin your version: the wire
protocol and CLI flags may change between minor releases; breaking changes are
called out in [CHANGELOG.md](CHANGELOG.md).

## Security

Mabo Tunnel carries other people's traffic across a trust boundary. Please read
[SECURITY.md](SECURITY.md) before reporting anything, and **never open a public
issue for a vulnerability**.

## License

[MIT](LICENSE) © Maborak Technologies Inc.
