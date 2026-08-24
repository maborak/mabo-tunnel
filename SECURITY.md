# Security Policy

Mabo Tunnel carries other people's traffic across a trust boundary. A bug here can
expose a private service to the internet or leak one tenant's traffic to
another, so security reports get priority over everything else.

## Supported versions

Mabo Tunnel is a young project. Only the latest release and `main` receive security fixes.

| Version | Supported |
|---------|-----------|
| latest release | ✅ |
| `main` | ✅ |
| anything older | ❌ |

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting:

1. Go to the [Security tab](../../security/advisories/new) of this repository.
2. Click **Report a vulnerability**.
3. Include the details below.

That channel is private until a fix ships, and it lets us credit you in the
advisory. If it is unavailable to you for any reason, open a regular issue that
says only *"security report, please open a private channel"* — with **no
technical detail** — and a maintainer will follow up.

### What to include

- The version or commit SHA you tested.
- Which identity the attack requires: an unauthenticated stranger, a
  `free`-plan tenant, a `pro`-plan tenant, a tenant running a modified client,
  or an operator.
- A concrete reproduction — the exact requests, or the exact frame bytes.
- The impact: what an attacker reaches, reads, or breaks that they should not.
- Your assessment of severity, and whether the issue is already public.

### What to expect

| Stage | Target |
|-------|--------|
| Acknowledgement | 72 hours |
| Initial assessment (confirmed / needs info / not a vulnerability) | 7 days |
| Fix or a documented mitigation for confirmed high/critical issues | 30 days |
| Public advisory | after the fix ships, or 90 days, whichever comes first |

We will keep you updated if a fix needs longer, and we will not disclose your
report before you have had a chance to review the advisory.

## Scope

### In scope

- Anything that lets one tenant reach, observe, or redirect **another tenant's
  traffic**.
- Subdomain prediction, enumeration, or takeover after a tunnel disconnects.
- Authentication and authorization bypass, including quota bypass
  (`PlanLimits`) and rate-limiter evasion.
- Wire-protocol abuse: malformed frames that panic the process, cause
  out-of-bounds access, or address another tunnel's connections. **A panic in a
  per-connection goroutine takes the whole server down**, so these are treated
  as high severity by default.
- HTTP request smuggling or header injection across the proxy boundary, in
  either direction.
- Anything that lets a remote party reach the client's local dashboard API
  (`/_api/*`, `/_dashboard/`), which is meant to be loopback-only.
- Resource exhaustion by one tenant that degrades other tenants or the server.
- Secrets leaking into logs, error messages, or responses.

### Out of scope — these are by design

Please read [`docs/security.md`](docs/security.md) before reporting; the
following are documented, intentional properties, not bugs:

- **A tunnel exposes a private service to the internet.** That is the product.
  A user choosing to tunnel something sensitive is their decision.
- **An un-gated tunnel is reachable by anyone who knows the subdomain.** IP
  allowlists and Basic Auth are opt-in per tunnel. A *bypass* of a gate that
  was requested is in scope; the absence of a gate that was not requested is
  not.
- **The AIO build's embedded secrets are obfuscated, not encrypted at rest.**
  Both halves of the key ship inside the same binary. `docs/security.md`
  documents exactly what an attacker recovers from a decompiled AIO binary and
  how to shrink the blast radius. Reports that the obfuscation is reversible
  will be closed as documented; reports that a *new* secret is embedded without
  the operator being told will not.
- **The WebSocket upgrader accepts any `Origin`.** Deliberate for a public
  tunnel entry point — the token is the control, not the origin. A finding is
  available if origin becomes load-bearing somewhere it should not be.
- **`--trusted-proxies` misconfiguration.** Trusting a proxy that is not in
  front of you is an operator error. A way to *bypass* the check from an
  untrusted peer is a real finding.
- Missing rate limits on endpoints that are documented as unlimited, denial of
  service that requires more resources than a normal user has, and anything
  requiring physical or prior root access to the host.

## Operator security checklist

If you run Mabo Tunnel, these are yours to get right — see
[`docs/security.md`](docs/security.md) and
[`docs/deployment.md`](docs/deployment.md):

- Set `--trusted-proxies` to match the reverse proxy actually in front of you.
  Wrong value means either a bypassable IP gate or a broken one.
- Scope the Cloudflare API token to one zone, `Zone > DNS > Edit`, nothing
  else — or delegate `_acme-challenge` to a throwaway zone.
- Never commit `.env`, `data/users.txt`, `data/certs/`, or the generated
  `cmd/server/embedded.go`. All four are gitignored; keep them that way.
- Migrate any legacy plaintext user file with `mabo-tunnel-token migrate` — those
  lines are live credentials until you do.
- Treat an AIO binary as equivalent to the credentials inside it.

## Recognition

Confirmed reports are credited in the advisory and in `CHANGELOG.md` unless you
ask otherwise. There is no paid bug bounty program.
