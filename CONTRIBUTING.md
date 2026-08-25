# Contributing to Mabo Tunnel

Thanks for helping improve Mabo Tunnel. This guide covers the essentials; deeper
detail lives in [`docs/development.md`](docs/development.md).

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
**Security problems do not go in issues or PRs** — see [SECURITY.md](SECURITY.md).

## Getting started

```bash
git clone https://github.com/maborak/mabo-tunnel
cd mabo-tunnel
make build
make test
```

New to the codebase? [`docs/architecture.md`](docs/architecture.md) is the
fastest orientation: the package layering, the wire protocol, the concurrency
model, and the traps.

You need **Go 1.26+** (`go.mod` targets 1.26.6 and `GOTOOLCHAIN=auto` will
fetch it). No other system dependencies for a normal build.

## Before you open a PR

1. **Format & vet.**
   ```bash
   gofmt -l .        # should print nothing
   go vet ./...
   ```
2. **Test, with the race detector.**
   ```bash
   make test-race
   ```
   Add tests for new behavior. Integration tests live in `tests/`, edge cases in
   `tests/edge/`.
3. **Keep docs in sync.** If you change flags, the protocol, or the layout,
   update the relevant file in `docs/` and the tables in `README.md`.
   `docs/protocol.md` matters most — it is what a second
   implementation would be written from.
4. **Log the change.** Add a line under `## [Unreleased]` in
   [`CHANGELOG.md`](CHANGELOG.md).

## Code guidelines

- Match the surrounding style: wrap errors with `fmt.Errorf("...: %w", err)` and
  use structured `slog` logging.
- Every write to a `*websocket.Conn` must hold the owning `writeMu` — the read
  and write paths run on different goroutines.
- Prefer bounded buffers and non-blocking sends on shared hot paths (see how
  `ProxiedConn` / `StreamingConn` drop rather than block).
- Exported identifiers are the API: everything lives under `internal/`, so
  exporting a name is a claim that another package needs it. Doc comments on
  exported symbols start with the symbol's own name (`go vet` checks this) and
  should state concurrency safety and who owns closing any returned resource.
- Wire-format strings and frame constants live in `internal/protocol` and are
  referenced from there — never re-spelled as a literal in the server or client.
- `internal/server` and `internal/client` must never import each other; they
  agree only through `internal/protocol`. Verify with
  `go list -deps ./internal/server | grep internal/client` (should be empty).
- Don't commit secrets. `.env`, `data/users.txt`, `data/certs/` and the
  generated `cmd/server/embedded.go` are all gitignored; keep them that way.

## Commit & PR

- Use clear, imperative commit subjects (`fix: stream HTTP responses through
  tunnel instead of buffering`).
- Keep PRs focused; describe the problem, the change, and how you tested it.
- Reference related issues.

## Scope

Mabo Tunnel is a small, dependency-light tunnel service. Favor changes that keep the
single-binary, flat-file, no-database model intact. Larger architectural shifts
are worth an issue/discussion first.
