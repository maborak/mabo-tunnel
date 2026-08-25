# Deployment

Two supported topologies:

1. **Docker + Caddy** — Mabo Tunnel in plain HTTP mode behind Caddy, which
   terminates TLS with wildcard certs (Cloudflare DNS-01). Good when you
   already run Caddy or want a battle-tested TLS front door.
2. **All-in-one (AIO)** — a single hardened binary that serves `:80`/`:443`
   and provisions its own certs. Good for zero-dependency single-host deploys.

Both need a **DNS wildcard** pointing your base domain and `*.base-domain` at
the host, plus a **Cloudflare API token** with DNS edit rights on that zone
(used for the DNS-01 ACME challenge).

## DNS

```
tunnel.example.com      A     203.0.113.10
*.tunnel.example.com    A     203.0.113.10
```

Every tunnel is a subdomain of the base domain, so the wildcard record is
required. TLS uses the DNS-01 challenge, so the host does not need port 80
reachable for issuance (but you'll want 80/443 open for traffic).

## Docker + Caddy

`docker-compose.yml` runs two services: `mabo-tunnel` (plain HTTP on `:8080`,
internal) and `caddy` (public `:80`/`:443`, TLS termination, reverse proxy).

```bash
# 1. Provide the Cloudflare token (used by Caddy for DNS-01).
echo "CF_API_TOKEN=your-token" > .env
# Optional: pin the public bind IP (default 0.0.0.0)
# echo "BIND_IP=203.0.113.10" >> .env

# 2. Add your users.
$EDITOR data/users.txt

# 3. Start.
docker compose up -d
```

Key files:

- **`Dockerfile`** — builds `mabo-tunnel-server`, runs as non-root, healthchecks
  `/health`, defaults to `--addr=:8080 --users-file=/app/data/users.txt`.
- **`Caddyfile`** — serves `tunnel.example.com` + `*.tunnel.example.com`, reverse
  proxies to `mabo-tunnel:8080` over HTTP/1.1 (so WebSocket upgrades pass through),
  and gets TLS via `dns cloudflare {env.CF_API_TOKEN}`. **Edit the domain to
  match yours.**
- **`docker-compose.yml`** — mounts `data/users.txt` read-only, gates Caddy on
  the mabo-tunnel healthcheck, exposes 80/443 (+443/udp for HTTP/3).

To change the domain, edit `Caddyfile` (both the site block and the `tls` line
target the base domain) and pass `--domain` to the server via the compose
`command:` or `MABO_TUNNEL_DOMAIN`.

> [!WARNING]
> Do **not** run `--upgrade` inside the container. The swapped binary lives only
> in the container's writable layer and is lost when the container is recreated.
> Upgrade by rebuilding instead:
>
> ```bash
> docker compose build --pull && docker compose up -d
> ```

### Why HTTP/1.1 to the backend

The Caddy `reverse_proxy` uses `versions 1.1` so WebSocket upgrades (client
`/tunnel/connect` and proxied app WebSockets) are forwarded correctly. Keep
that if you customize the config.

## All-in-one binary

Build a self-contained server binary with its config embedded, copy it to the
host, and run it — no config files or env at runtime.

```bash
make build-aio \
  AIO_DOMAIN=tunnel.example.com \
  AIO_EMAIL=admin@example.com \
  CF_API_TOKEN=xxx \
  AIO_GOOS=linux AIO_GOARCH=amd64

scp build/mabo-tunnel-server-linux-amd64 host:/usr/local/bin/mabo-tunnel-server
ssh host '/usr/local/bin/mabo-tunnel-server'
```

A native build writes `build/mabo-tunnel-server`; a cross-compiled one is named for
its target, as above.

`make build-aio-all` builds every platform at once. The full list of build
variables — cert path, bind IP, users file, version stamp — is in
[development.md](development.md#aio-builds-embedded-config); what ends up
inside the binary and how well it is protected is in
[security.md](security.md).

On first start the binary provisions certificates for the domain and its
wildcard, so the host needs outbound network, a Cloudflare zone it can edit,
and a writable `AIO_CERT_PATH`. Back that directory up or expect a re-issue
(and Let's Encrypt rate limits) if the host is rebuilt.

Or run AIO from a normal build with explicit flags:

```bash
./mabo-tunnel-server --aio \
  --domain=tunnel.example.com \
  --aio-email=admin@example.com \
  --aio-cf-token=$CF_API_TOKEN
```

Open **80** and **443** (TCP; 443/udp too if you want HTTP/3 upstream) and the
**TCP tunnel range** (default `10000–10100`) if you use TCP tunnels.

## Operational checks

- **Liveness:** `GET /health` → `200`.
- **Readiness:** `GET /ready` → `503` until at least one user is loaded, then
  `200` with active tunnel + user counts. Wire this into your probe.
- **Logs:** structured `slog` text on stdout; watch for `removing stale tunnel`,
  `subdomain reserved for reconnect`, and `authentication failed`. Per-request
  lines and source locations are at `--log-level=debug`.

## Firewall summary

| Port | Who | Mode |
|------|-----|------|
| 80 | public | AIO (ACME + HTTP), or Caddy |
| 443 | public | AIO (HTTPS), or Caddy (+udp for HTTP/3) |
| 8080 | internal only | plain-mode HTTP (behind Caddy) |
| 4443 | public | plain mode with `--tls` |
| 10000–10100 | public | TCP tunnels (configurable) |

---

**More:** [architecture](architecture.md) · [protocol](protocol.md) ·
[server](server.md) · [client](client.md) · [deployment](deployment.md) ·
[security](security.md) · [development](development.md) · [FAQ](faq.md) ·
[troubleshooting](troubleshooting.md)
