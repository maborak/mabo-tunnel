# Changelog

All notable changes to Mabo Tunnel are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
