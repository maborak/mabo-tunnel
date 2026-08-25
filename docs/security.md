# Security

## Authentication

- **Token-based.** Each user has a pre-generated token stored in
  `data/users.txt` as `sha256:<hex>:username:plan` — only the hash is stored.
  There are no passwords.
- A presented token is hashed and looked up by hash. The token is never stored,
  so there is nothing in the file — or in a binary embedding it — to steal and
  replay. Lookup is a single map operation regardless of user count.
- Failed auth attempts are **rate-limited to 5 per minute per source IP**
  (`internal/auth`), with expired entries swept and total tracked addresses
  capped. The source IP comes from `X-Forwarded-For` only when the request
  arrived from a trusted proxy (`--trusted-proxies`); see below.
- The auth handshake has a 10s deadline and must be the first WebSocket message.

Generate a token:

```bash
mabo-tunnel-token generate alice pro >> data/users.txt
```

The token is printed once, to stderr. It cannot be recovered afterwards — if a
user loses theirs, issue a new one.

### Migrating a plaintext user file

Files in the old `token:username:plan` form still load, so upgrading the server
breaks nothing, but the server logs a warning counting the unhashed entries.
Those lines are live credentials. Convert them:

```bash
mabo-tunnel-token migrate data/users.txt
```

The original is kept as `users.txt.plaintext.bak` (mode 0600). Restart the
server, confirm clients still connect, then destroy it — existing tokens keep
working, since only the storage format changed.

## Tunnel isolation & access control

- Subdomains are 64-bit random hex (`generateSubdomain`), harder to enumerate
  than short slugs. Tunnel IDs are 128-bit.
- Plan quotas cap concurrent tunnels per user (`free` 1, `pro` 10).
- **HTTP Basic Auth** (`--auth user:pass`, or per-tunnel in YAML) protects a
  tunnel's public endpoint; credentials are checked in constant time.
- **IP allow/deny lists** are enforced by the server (`checkIPAccess`: deny
  list first, then allow list if non-empty). ⚠️ **The bundled CLI does not set
  them** — no flag/YAML key populates `allowed_ips`/`denied_ips`, so this
  control is currently unreachable without a custom client; wiring CLI/YAML
  support for it is on the roadmap.

## Request limits

- HTTP request bodies over **10 MiB** are rejected with `413` and the tunnel
  owner is notified (`notice` / `body_too_large`). Known-length uploads are
  rejected up front; chunked bodies are capped mid-stream via `MaxBytesReader`.
- WebSocket frames are capped at **16 MiB** on both ends.
- A slow public consumer that backs up the per-request event buffer (512 slots)
  or the WS-passthrough channel (64 slots) has its connection dropped rather
  than being allowed to stall the shared tunnel read loop.

## Transport security

- **AIO mode** provisions Let's Encrypt certs (via CertMagic) for the base
  domain and wildcard using the Cloudflare DNS-01 challenge; ALPN offers
  `h2` and `http/1.1`.
- **Plain mode** expects a TLS-terminating reverse proxy in front.
- The WebSocket upgrader uses `CheckOrigin → true` (any origin). This is
  intentional for a public tunnel entry point but means origin is not a control
  surface; rely on the token instead.

## AIO build with embedded config

`make build-aio` / `build-aio-all` bake configuration and secrets **into** the
server binary, encrypted, so no `users.txt`, token, or env is needed at
runtime. The point is not to distribute those as loose files, and to keep them
out of a plain `strings` dump.

### How it works

`embed-secrets` generates a random 32-byte key, encrypts the Cloudflare token
and the users database with it (AES-256-GCM), and writes
`cmd/server/embedded.go`: an `init()` that decrypts them at startup. The key is
stored as two XOR halves that are joined at runtime. The server is then built
once with `-ldflags="-w -s"` to strip symbols.

### Caveat: this is obfuscation, not encryption at rest

Both halves of the key ship inside the same binary, so anyone who has the
binary can recover whatever it embeds — by running it, or by reading the
decompiled `init()`. This is a property of shipping a self-decrypting binary,
not a defect that stronger obfuscation fixes.

**What an attacker gets from a decompiled AIO binary:**

| Embedded value | Exposure |
|----------------|----------|
| domain, bind IP, ACME email, cert path | Not secret. No impact. |
| user database | Hashes only. **Not usable** — cannot be replayed as tokens. |
| Cloudflare API token | **Fully usable.** Real credential, real blast radius. |

Only the last row matters, and it is the reason to think carefully about
distributing AIO binaries at all.

### Reducing the Cloudflare token's blast radius

CertMagic must call the Cloudflare API with the live token to answer DNS-01, so
it cannot be hashed. Shrink what it can do instead, in increasing order of
effectiveness:

1. **Do not embed it.** Build without `CF_API_TOKEN` and supply it on the host
   via env or a root-only file. A leaked binary then leaks nothing usable.
2. **Scope the token.** One token, one zone, `Zone > DNS > Edit` and nothing
   else. An account-wide token turns a binary leak into a full DNS compromise.
3. **Delegate the challenge.** CNAME `_acme-challenge.<domain>` to a throwaway
   zone (or run [acme-dns](https://github.com/joohoi/acme-dns)) and scope the
   token to that zone only. A leak then cannot touch your real records — no
   cert issuance for other names, no MX or A record tampering.

Wildcard certificates require DNS-01, so some DNS-capable credential must
exist. The goal is to make it a credential that is worthless if stolen.

### If a binary has already been decompiled

Treat the Cloudflare token as public: **revoke** it in the Cloudflare dashboard
(revoking is not the same as rotating — the old value must stop working), issue
a scoped replacement, and review the zone's audit log for records you did not
create. Hashed user entries need no action; plaintext ones do — rotate every
token that was in an unhashed file.

## Self-update trust model

`--upgrade` verifies a downloaded binary against the release's `SHA256SUMS.txt`.
That protects against truncated or corrupted downloads — it does **not** protect
against a compromised release pipeline, because the checksum file travels over
the same channel (and comes from the same signer) as the binary itself. Treat a
compromised release as game over for self-updating installs, exactly as it would
be for manual downloads. There is no code signing or notarization. An optional
`GH_TOKEN`/`GITHUB_TOKEN` environment variable raises the GitHub API rate limit
and is required while this repository is private.

## Reporting

See [`SECURITY.md`](../SECURITY.md) at the repository root for the reporting
process, response targets, and what is in and out of scope.

**Never open a public issue for a vulnerability.** Use GitHub's private
vulnerability reporting from the repository's Security tab.

---

**More:** [architecture](architecture.md) · [protocol](protocol.md) ·
[server](server.md) · [client](client.md) · [deployment](deployment.md) ·
[security](security.md) · [development](development.md) · [FAQ](faq.md) ·
[troubleshooting](troubleshooting.md)
