<!--
Thanks for contributing. Keep the PR focused — one problem per PR reviews far
faster than a bundle.

If this fixes a security issue, do NOT describe the vulnerability here.
See SECURITY.md.
-->

## What and why

<!-- The problem, then the change. A reviewer should understand the bug before
     they read the diff. -->

Fixes #

## How it was tested

<!-- Not "tests pass" — say what you actually exercised. If the change touches
     the proxy path, say whether you ran a real request through a real tunnel. -->

## Checklist

- [ ] `gofmt -l .` prints nothing
- [ ] `go vet ./...` is clean
- [ ] `make test` passes
- [ ] `make test-race` passes — **required** if this touches goroutines,
      channels, locks, or anything on the proxy data path
- [ ] Tests added or updated for the changed behaviour
- [ ] No secrets, tokens, or real hostnames in the diff

## Docs

- [ ] Flags, env vars, or defaults changed → updated `docs/server.md` /
      `docs/client.md` and the tables in `README.md`
- [ ] Wire format changed → updated `docs/protocol.md`
- [ ] Nothing user-visible changed, so no docs needed

## Compatibility

- [ ] No wire-protocol change
- [ ] Wire-protocol change, and it degrades safely against a peer that does not
      support it <!-- see how AuthRequest.Binary is negotiated -->
- [ ] Breaking change <!-- describe the migration below -->

<!-- If breaking: what breaks, for whom, and what they need to do. -->
