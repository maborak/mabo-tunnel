# Development

## Requirements

- **Go 1.26+.** `go.mod` declares `go 1.26.1`; the Docker build uses
  `golang:1.26-alpine` with `GOTOOLCHAIN=local`.

## Build & run

```bash
make build              # server + client + token tool → build/
make build-server       # server only
make build-client       # client only
make build-token        # mabo-tunnel-token only

make run-server         # server on :8080, domain $MABO_TUNNEL_DOMAIN (from .env)
make run-server-local   # server on :8080, domain localhost
make run-client         # client → $MABO_TUNNEL_SERVER (from .env)
make run-client-local   # client → ws://localhost:8080

make build-all          # cross-compile server+client (no AIO)
make clean              # remove build/
```

Run directly during development:

```bash
go run ./cmd/server --domain=localhost --addr=:8080
go run ./cmd/client --server=ws://localhost:8080 --token=$MABO_TUNNEL_TOKEN --port=3000
```

With `--domain=localhost`, tunnels are reachable at
`http://<subdomain>.localhost:8080` (works out of the box on most systems since
`*.localhost` resolves to loopback).

## AIO builds (embedded config)

An AIO binary carries its own configuration, so it runs with no flags, no
environment, and no `users.txt` on the host.

### Targets

```bash
make build-aio          # current platform, symbols stripped
make build-aio-all      # linux/{amd64,arm64}, darwin/{amd64,arm64}, windows/amd64
make build-aio-dev      # native platform, symbols kept — for testing
```

### Variables

Every one is a normal make variable: set it on the command line, or in `.env`
(the Makefile does `-include .env` and exports it).

| Variable | Default | Embedded as | Notes |
|----------|---------|-------------|-------|
| `CF_API_TOKEN` | — | Cloudflare token (**encrypted**) | Required. Needs Zone > DNS > Edit on the zone |
| `AIO_EMAIL` | `$(MABO_TUNNEL_AIO_EMAIL)` | ACME email | Required. Either name works in `.env` |
| `AIO_DOMAIN` | `tunnel.example.com` | base domain | Certs are issued for this **and** `*.this` |
| `AIO_BIND` | `$(BIND_IP)`, else `0.0.0.0` | bind IP | Which interface :80/:443 listen on |
| `AIO_CERT_PATH` | `data/certs` | cert cache dir | Path **on the deploy host**, must be writable |
| `AIO_USERS` | `data/users.txt` | user database (**encrypted**) | Read at build time. Stores token hashes, so it is not a credential list |
| `AIO_GOOS` | host OS | — | Target OS (`build-aio` only) |
| `AIO_GOARCH` | host arch | — | Target arch (`build-aio` only) |
| `VERSION` | `git describe` | — | Stamped into `/` endpoint output |

### Output names

`build-aio` writes `build/mabo-tunnel-server` for a native build, and
`build/mabo-tunnel-server-<goos>-<goarch>` when cross-compiling, so a binary for
another platform is never mistaken for a native one. `build-aio-all` always
uses the suffixed form. Windows targets get `.exe`.

### Examples

Minimal — everything else defaulted:

```bash
make build-aio AIO_EMAIL=admin@example.com CF_API_TOKEN=xxx
```

Everything specified, cross-compiled for a Linux server:

```bash
make build-aio \
  AIO_DOMAIN=tunnel.example.com \
  AIO_EMAIL=admin@example.com \
  CF_API_TOKEN=xxx \
  AIO_BIND=203.0.113.10 \
  AIO_CERT_PATH=/var/lib/mabo-tunnel/certs \
  AIO_USERS=./prod-users.txt \
  AIO_GOOS=linux AIO_GOARCH=amd64 \
  VERSION=1.4.0
```

Or put the stable values in `.env` and just run `make build-aio`:

```bash
CF_API_TOKEN=xxx
AIO_EMAIL=admin@example.com
AIO_DOMAIN=tunnel.example.com
BIND_IP=203.0.113.10
```

### What is and is not embedded

Embedded: `AIO=true`, domain, bind IP, ACME email, cert path (all plaintext in
the generated source), plus the Cloudflare token and the user database
(AES-256-GCM). The user database holds token *hashes*, so it is not usable even
once decrypted; the Cloudflare token is a live credential and is the one thing
worth protecting here.

**Not** embedded, so still flags or env on the host if you need non-defaults:
`--tcp-port-min` / `--tcp-port-max`, `--log-level`, `--trusted-proxies`.
Embedded values are *fallbacks* — a flag or env var still wins.

Never embedded: **TLS certificates**. Those are issued at first start from
Let's Encrypt over DNS-01 and cached to `AIO_CERT_PATH`, so the host still needs
outbound network, a reachable Cloudflare zone, and a writable cert directory.

### Verifying a build

```bash
make build-aio AIO_EMAIL=admin@example.com CF_API_TOKEN=xxx
strings build/mabo-tunnel-server | grep -c 'xxx'   # expect 0
./build/mabo-tunnel-server --help                  # binary is runnable
```

Build artifacts are generated into `cmd/server/embedded.go` and deleted
afterwards. If a build fails partway, check that it is gone — it holds your
encrypted config. It is gitignored, so it cannot be committed by accident.

> The embedded secrets are obfuscated, not protected: the key ships in the same
> binary. See [security.md](security.md).

## Tests

```bash
make test               # go test ./...
make test-race          # go test -race ./...
```

Test layout:

| File | Scope |
|------|-------|
| `tests/proxy_test.go` | HTTP proxy integration |
| `tests/functional_test.go` | End-to-end functional flows |
| `tests/streaming_test.go` | Streaming response path (SSE/chunked) |
| `tests/edge/edge_test.go` | Edge cases |

## Project layout

```
cmd/
  server/          server entry point (+ generated embedded.go in AIO builds)
  client/          client CLI
  embed-secrets/   build tool: encrypt + embed AIO config
  mabo-tunnel-token/   generate tokens, migrate users.txt to hashes
internal/
  server/          tunnel mgmt, HTTP/TCP proxy, WS handler, auth handshake
  client/          connection, forwarding, TUI, dashboard, inspector
  protocol/        shared message types + serialization
  auth/            users.txt store, token check, rate limiter
  config/          mabo-tunnel.yml loader
  secrets/         AES-256-GCM + XOR-split key for embedded config
  version/         build version, single source
tests/             integration + edge tests
data/              users.txt, certs/ (AIO cert cache)
docs/              this documentation
```

See [architecture.md](architecture.md) for how these fit together and
[protocol.md](protocol.md) for the wire format.

## Conventions

- Keep `docs/server.md` and `docs/client.md` in sync with the actual flags and
  defaults, and keep the protocol message table current.
- Log all notable changes under `## [Unreleased]` in [`CHANGELOG.md`](../CHANGELOG.md).
- WebSocket writes are always guarded by the relevant `writeMu`; do not write to
  a `*websocket.Conn` from more than one goroutine without it.
- Match the surrounding code's error-wrapping (`fmt.Errorf("...: %w", err)`) and
  `slog` structured-logging style.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md).

---

**More:** [architecture](architecture.md) · [protocol](protocol.md) ·
[server](server.md) · [client](client.md) · [deployment](deployment.md) ·
[security](security.md) · [development](development.md) · [FAQ](faq.md) ·
[troubleshooting](troubleshooting.md)
