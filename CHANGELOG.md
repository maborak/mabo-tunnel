# Changelog

All notable changes to Mabo Tunnel are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Client IP allow/deny flags** — `--allow-ip` / `--deny-ip` (repeatable,
  comma-separated) plus `allow_ips` / `deny_ips` YAML keys; carried by the
  auth handshake's existing `allowed_ips` / `denied_ips` fields. The edge now
  matches these lists as real CIDR networks (a bare IP becomes /32 or /128),
  replacing the previous exact-string comparison. The README note that the
  client had no way to set them is hereby retired.
- **Per-user tunnel quotas** — the users file accepts an optional fourth
  field: `sha256:<hex>:username:plan:<max-tunnels>` (legacy plaintext form
  too). It overrides the plan default. Plan defaults themselves are
  configurable via `--plan-free-tunnels` / `--plan-pro-tunnels`
  (env: `MABO_TUNNEL_PLAN_FREE_TUNNELS` / `MABO_TUNNEL_PLAN_PRO_TUNNELS`).
- **Hot user reload** — the users file is polled every 5s and reloaded on
  change, and `SIGHUP` forces a reload. A file that fails to parse keeps the
  previously loaded users instead of locking every token out.
- **Admin API + Prometheus metrics** — `--admin-token`
  (env: `MABO_TUNNEL_ADMIN_TOKEN`) enables:
  - `GET /admin/tunnels` — active tunnels with in-flight counts
  - `DELETE /admin/tunnels/{id}` — revoke a tunnel immediately (no reconnect
    reservation)
  - `POST /admin/users/reload` — reload the users file
  - `GET /admin/stats` — version, uptime, counts
  - `GET /metrics` — Prometheus text format (`mabo_tunnels_active`,
    `mabo_http_requests_total`, `mabo_auth_failures_total`, …)
  With no token set, all five answer 404: probing cannot even confirm they
  exist.
- **ACME DNS provider choice** — AIO mode's DNS-01 challenge is no longer
  Cloudflare-only: `--aio-dns-provider` selects `cloudflare`,
  `digitalocean`, or `route53`; `--aio-cf-token` carries whichever single
  credential the provider needs (DO token / AWS Access Key ID) and
  `--aio-dns-secret` the second one (AWS Secret Access Key). The embed flow
  encrypts all three values.
- **Custom domains** — servers started with `--custom-domains=zone.tld,…`
  let users point their own hostnames at a tunnel. Ownership is proven at
  connect time via a TXT record `_mabo-challenge.<domain>` whose value is
  sha256 of "<token-hash>.<domain>" — derivable only from the real token.
  Verified hosts get on-demand certificates (AIO) with issuance denied for
  anything that is not an active custom domain. Client side:
  `--custom-domain` flag or per-tunnel `custom_domain:` YAML key.
- **Per-tunnel rate limiting** — `--tunnel-rps` /
  env `MABO_TUNNEL_TUNNEL_RPS` caps each tunnel's public request rate with a
  token bucket (`--tunnel-burst` allows an instant burst); over-limit
  requests get `429` + `Retry-After`. Default remains unlimited.
- **Dashboard HAR export** — `GET /_api/tunnels/:id/har` renders captured
  traffic as HAR 1.2 (`?download=1` to save). WebSocket sessions appear as
  101 entries with the Chrome-style `_webSocketMessages` extension.
- **WebSocket inspection** — WS passthrough sessions are captured per
  connection (up to 50 chunks of 512 B each, direction-labeled, binary
  detected and hex-encoded) and visible through the dashboard API and HAR
  export.

### Fixed

- The users parser no longer treats `|` inside comment lines as an entry
  separator. Previously a comment such as
  `# generate <username> [free|pro] >> data/users.txt` was split at the pipe,
  producing a bogus entry (`pro] >> data/users.txt`) that made the server — and
  every AIO build embedding that file — refuse to start.

### Changed

- AIO builds now validate and normalize the users file **at build time**:
  `embed-secrets` embeds only canonical hashed entries
  (`sha256:<hex>:username:plan`), never comments or plaintext tokens, and a
  malformed users file fails the build instead of server startup on the host.

## [1.1.1] - 2026-08-25

### Fixed

- `--upgrade` on private repositories: release assets are now downloaded through
  the GitHub API (which honors `GH_TOKEN`) instead of the browser download URL,
  and a request-lifecycle bug that aborted every binary download with "context
  canceled" is fixed.

## [1.1.0] - 2026-08-25

### Added

- `--upgrade` on both `mabo-tunnel-client` and `mabo-tunnel-server`: self-update
  from GitHub Releases with sha256 verification against the release's
  `SHA256SUMS.txt` and an atomic in-place binary swap (new `internal/upgrade`
  package, stdlib only). Dev builds always install the latest release;
  AIO-embedded server builds refuse unless `--force-upgrade` is given.
- `--version` and `--force-upgrade` flags on both binaries.

### Changed

- Releases are now built and published by GoReleaser (`.goreleaser.yml` +
  `goreleaser-action`). Asset names are unchanged (`mabo-tunnel-<bin>-<os>-<arch>`,
  plus `SHA256SUMS.txt`), so existing download URLs keep working.
  Re-running a release via the workflow's `workflow_dispatch` tag input is gone —
  delete and re-push the tag instead.

## [1.0.0] - 2026-08-24

### Added

- Initial public release.
- HTTP and TCP tunnels multiplexed over a single authenticated WebSocket,
  with an optional binary framing mode negotiated at auth time.
- Token-based auth (`sha256` hashes on disk), free/pro plans with tunnel
  quotas and rate limiting.
- Streaming request/response bodies end to end (SSE and chunked pass-through
  never buffer).
- All-in-one server mode (`--aio`): HTTP :80 + HTTPS :443 with automatic
  Let's Encrypt certificates via Cloudflare DNS-01.
- Local client dashboard: live request inspector, replay, copy-as-cURL.
- Terminal UI, YAML config file, Docker + Caddy deployment, cross-compiled
  AIO builds.
