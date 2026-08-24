# FAQ

## What Mabo Tunnel is

### What problem does it solve?

You have something running on `localhost` and you need a public URL for it — a
webhook from Stripe or GitHub, a demo for a colleague, an OAuth callback, a
mobile device testing against your laptop. Mabo Tunnel gives you that URL on **your
own domain, from your own server**.

### How is it different from hosted tunnel services?

The difference is who owns the endpoint.

| | Mabo Tunnel | Hosted tunnel services |
|---|---|---|
| Who runs the public endpoint | You | The vendor |
| Your traffic passes through | Your VPS | Their infrastructure |
| Domain | Yours | Theirs, or yours on a paid tier |
| Account / seats / request caps | None | Usually |
| Setup cost | A VPS, a domain, a wildcard DNS record | Sign up |
| Global edge network, WAF, replay UI, team management | No | Often yes |

Mabo Tunnel is not trying to beat those products on features. It exists for the case
where you already have a server and would rather not route your traffic through
a third party.

### Is it production-ready?

Yes, and it is used in production by its authors. It is a young 1.x project,
so pin your version: the wire protocol and CLI flags may change between minor
releases, with breaking changes called out in
[`CHANGELOG.md`](../CHANGELOG.md).

### Is it a load balancer / API gateway / VPN?

No. It moves traffic from a public subdomain to one local service, and that is
all. It does not terminate application auth, rewrite paths, balance across
backends, or give you a private network between machines. If you want a mesh,
you want WireGuard or Tailscale.

---

## Running it

### What do I need to self-host?

A VPS with a public IP, a domain, and a **wildcard DNS record**:

```
tunnel.example.com.    A    203.0.113.10
*.tunnel.example.com.  A    203.0.113.10
```

Then either AIO mode (the binary handles TLS itself) or a reverse proxy such as
Caddy in front. Both are covered in [`deployment.md`](deployment.md).

### Do I need Cloudflare?

Only for **automatic wildcard certificates** in AIO mode, which uses the
Cloudflare DNS-01 challenge. Wildcard certificates cannot use HTTP-01, so some
DNS-capable credential is required. Alternatives: run behind Caddy with your own
DNS provider plugin, or supply a certificate you obtained yourself.

### Can I run the server and client on the same machine?

Yes — that is the quick start, and how the test suite works. Use
`--domain=localhost` and `--server=ws://localhost:8080`.

### Why does my freshly built client try to connect to localhost?

Because binaries built from this repository default to a local server on
purpose. A public project must never ship a binary that quietly talks to its
maintainer's infrastructure. Set `--server` / `MABO_TUNNEL_SERVER`, or bake your own
default at build time:

```bash
go build -ldflags "-X main.defaultServerURL=wss://tunnel.example.com" ./cmd/client
```

### How do I add users?

Tokens are generated on the server and distributed out of band:

```bash
mabo-tunnel-token generate alice pro >> data/users.txt
```

The token prints once, to stderr. The file stores only `sha256(token)`, so it is
not a list of working credentials — and losing a token means issuing a new one,
not recovering the old.

### How do I revoke a token?

Remove the line and **restart the server**. `users.txt` is read at startup only,
and an already-established tunnel authenticated before the edit keeps running.
Live reload is not implemented yet; until it lands, "restart" is the honest
answer.

### Can several people share one server?

Yes — that is the design. Each user gets a token and a plan, and plans cap
concurrent tunnels (`free` 1, `pro` 10). There is no per-user bandwidth or
request-rate limit yet.

### Is there a Docker image?

There is a `Dockerfile` and a `docker-compose.yml` with a Caddy sidecar in the
repository. No image is published to a registry yet — build it yourself.

---

## Using it

### Are my subdomains stable?

A random subdomain changes on every fresh connect, but:

- `--subdomain=myapp` requests a specific one.
- Named tunnels (`--port=ui:5173`) get `<username>_ui`, which is stable.
- After a disconnect the subdomain is reserved for 5 minutes, so a reconnect
  keeps its URL.

### Can I expose several services at once?

Yes, over the same connection:

```bash
mabo-tunnel-client --token=$TOKEN --port=ui:5173,api:9001
```

### Can I tunnel to something that is not on this machine?

Yes — `--port=ui:192.168.0.40:5173` forwards to any host the client can reach.
The client is the only thing that needs to be on that network.

### Does it work with SSE, streaming APIs, or LLM token streams?

Yes, and this is deliberate. Responses are forwarded chunk by chunk with no
overall deadline once headers arrive, so a stream behaves the way it does
locally. If output is arriving in one lump, something else in the path is
buffering — see [`troubleshooting.md`](troubleshooting.md#sse-or-streamed-responses-arrive-all-at-once).

### Can the tunnelled app serve its own WebSockets?

Yes, passed through end to end.

### Can I tunnel a database or SSH?

Yes, with `--protocol=tcp`. The server allocates a port from its TCP range
(default 10000–10100).

```bash
mabo-tunnel-client --token=$TOKEN --port=5432 --protocol=tcp
```

Think carefully before pointing the internet at a database. Use a per-tunnel IP
allowlist — bearing in mind the client cannot set one yet — or an SSH tunnel
instead.

### How big can a request be?

10 MiB for an HTTP request body. Larger ones get a `413` and the tunnel owner
sees a `body_too_large` notice. Responses are not capped. Full table in
[`README.md`](../README.md#limits-and-timeouts).

### Can I use it as a permanent public host for a site?

Technically yes; it is not what the design optimizes for. Every request crosses
an extra hop and depends on the client process staying alive on your machine.
For a permanent site, deploy the site.

---

## Security

### Is my traffic encrypted?

Between the public internet and your server: yes, if you terminate TLS (AIO mode
or a reverse proxy). Between the server and the client: yes, when the client
dials `wss://`. Between the client and your local service: plain HTTP over
loopback, unless the local service itself speaks TLS. Mabo Tunnel does not add
end-to-end encryption on top — your server sees the plaintext, which is
inherent to being a reverse proxy.

### Anyone with the URL can reach my service. Is that safe?

It is exactly as safe as putting the service on the internet, because that is
what you did. Subdomains are 64-bit random values, so they are not guessable,
but obscurity is not a control. For anything sensitive, add `--auth user:pass`,
or keep the tunnel short-lived.

### How are tokens stored?

As `sha256:<hex>` in `data/users.txt`. The file is not a credential list, and a
token cannot be recovered from it. Legacy plaintext files still load with a
startup warning — `mabo-tunnel-token migrate` converts them.

### Is the AIO binary's embedded secret safe?

**No, and the documentation says so plainly.** Both halves of the decryption key
ship inside the same binary, so anyone holding it can recover the Cloudflare
token and the user database. The user database is hashes, which is harmless; the
Cloudflare token is a real credential. Scope it to one zone, or do not embed it.
[`security.md`](security.md#caveat-this-is-obfuscation-not-encryption-at-rest)
covers the exposure and how to reduce it.

### I found a vulnerability.

Read [`SECURITY.md`](../SECURITY.md) and report it privately. Do not open a
public issue.

---

## Contributing

### How do I build and test?

```bash
make build
make test
make test-race   # required if you touch goroutines, channels, or the proxy path
```

The suite is fully in-process — no network, no fixed ports.

### What kinds of change are welcome?

Bug fixes, documentation, tests, and features that keep the shape: one Go
module, no database, flat-file auth, single binary. Anything that adds a
required external service is a hard sell. See [`CONTRIBUTING.md`](../CONTRIBUTING.md).

---

**More:** [architecture](architecture.md) · [protocol](protocol.md) ·
[server](server.md) · [client](client.md) · [deployment](deployment.md) ·
[security](security.md) · [development](development.md) · [FAQ](faq.md) ·
[troubleshooting](troubleshooting.md)
