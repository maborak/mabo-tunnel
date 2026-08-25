// Package upgrade self-updates a mabo-tunnel binary from the project's GitHub
// Releases: fetch the latest release, verify the downloaded asset against the
// release's SHA256SUMS.txt, and atomically replace the running executable.
// Stdlib only.
//
// The verification protects against truncated or corrupted downloads, not
// against a compromised release pipeline — SHA256SUMS.txt travels over the
// same channel as the binary itself.
package upgrade

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Status is the outcome of Run.
type Status int

const (
	StatusUpdated  Status = iota // swapped in a new binary
	StatusUpToDate               // current version >= latest, nothing done
)

// Options configures one upgrade attempt.
type Options struct {
	Owner   string // empty → DefaultOwner
	Repo    string // empty → DefaultRepo
	Binary  string // release-asset stem: "server" or "client"
	Current string // the running version, i.e. version.Version
	Force   bool   // reinstall even if already up to date
	BaseURL string // API base override for tests; empty → https://api.github.com
	Client  *http.Client
	Target  string // executable path to replace; empty → this process's binary (test hook)
	Stdout  io.Writer
	Stderr  io.Writer
}

// Result reports what Run did.
type Result struct {
	Status Status
	From   string // Current as passed in
	To     string // release tag of the installed binary
	Path   string // absolute path of the (possibly replaced) executable
}

// AssetName maps a binary stem plus platform to its release-asset name. It
// mirrors the archives.name_template in .goreleaser.yml exactly;
// TestAssetNamesMatchGoreleaser pins the two together.
func AssetName(binary, goos, goarch string) string {
	ext := ""
	if goos == "windows" {
		ext = ".exe"
	}
	return fmt.Sprintf("%s-%s-%s-%s%s", assetPrefix, binary, goos, goarch, ext)
}

func displayName(binary string) string { return assetPrefix + "-" + binary }

// Run performs the full upgrade flow: resolve the real executable, fetch the
// latest release, decide whether an install is needed, download + sha256-
// verify the platform asset into a temp file beside the executable, then
// atomically swap it in. The original binary stays byte-for-byte intact until
// the verified replacement is ready to rename over it.
func Run(ctx context.Context, opts Options) (Result, error) {
	out := opts.Stdout
	if out == nil {
		out = os.Stdout
	}
	errw := opts.Stderr
	if errw == nil {
		errw = os.Stderr
	}
	if opts.Binary == "" || strings.ContainsAny(opts.Binary, "/\\.") {
		return Result{}, fmt.Errorf("invalid binary stem %q", opts.Binary)
	}

	// Resolve the real executable (follow symlinks so a symlinked install
	// updates its target).
	exePath := opts.Target
	if exePath == "" {
		p, err := os.Executable()
		if err != nil {
			return Result{}, fmt.Errorf("locate executable: %w", err)
		}
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			p = resolved
		}
		exePath = p
	}
	fi, err := os.Stat(exePath)
	if err != nil {
		return Result{}, fmt.Errorf("stat %s: %w", exePath, err)
	}
	mode := fi.Mode().Perm()

	if _, err := os.Stat("/.dockerenv"); err == nil {
		fmt.Fprintln(errw, "Warning: container detected — the swapped binary lives only in "+
			"this container's writable layer and is lost on recreate; upgrade the image instead.")
	}

	owner := opts.Owner
	if owner == "" {
		owner = DefaultOwner
	}
	repo := opts.Repo
	if repo == "" {
		repo = DefaultRepo
	}
	gc := newGHClient(opts.BaseURL, opts.Client)

	rel, err := gc.fetchLatest(ctx, owner, repo)
	if err != nil {
		return Result{}, err
	}

	from := opts.Current
	to := rel.TagName
	cur, curOK := ParseVersion(from)
	lat, latOK := ParseVersion(to)
	if !opts.Force && curOK && latOK && CompareVersion(cur, lat) >= 0 {
		fmt.Fprintf(out, "%s %s is up to date (latest %s)\n", displayName(opts.Binary), from, to)
		return Result{Status: StatusUpToDate, From: from, To: to, Path: exePath}, nil
	}
	if !curOK && from != "" {
		fmt.Fprintf(errw, "Note: current version %q is not a release build; installing %s\n", from, to)
	}

	name := AssetName(opts.Binary, runtime.GOOS, runtime.GOARCH)
	if _, err := findAsset(rel, name); err != nil {
		return Result{}, fmt.Errorf("%w: need asset %s", err, name)
	}

	tmp, err := os.CreateTemp(filepath.Dir(exePath), "."+assetPrefix+"-upgrade-*")
	if err != nil {
		return Result{}, fmt.Errorf("create temp file beside %s: %w", exePath, err)
	}
	swapped := false
	defer func() {
		if !swapped {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()

	if err := gc.download(ctx, owner, repo, rel, name, tmp); err != nil {
		return Result{}, err
	}
	// CreateTemp makes 0600; restore the original permission bits (including
	// the exec bit) or the swapped-in binary won't run.
	if err := tmp.Chmod(mode); err != nil {
		return Result{}, fmt.Errorf("set permissions on temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return Result{}, fmt.Errorf("finalize temp file: %w", err)
	}
	if err := swapIn(tmp.Name(), exePath); err != nil {
		return Result{}, err
	}
	swapped = true

	fmt.Fprintf(out, "%s upgraded: %s → %s (%s)\n", displayName(opts.Binary), fromDisplay(from), to, exePath)
	fmt.Fprintf(out, "Restart %s to run the new version.\n", displayName(opts.Binary))
	return Result{Status: StatusUpdated, From: from, To: to, Path: exePath}, nil
}

// fromDisplay renders an empty/unparseable current version as "(dev)".
func fromDisplay(v string) string {
	if strings.TrimSpace(v) == "" {
		return "(dev)"
	}
	return v
}

// CLI is the thin wrapper the cmd entrypoints call for --upgrade: it runs the
// upgrade and returns a process exit code (0 success/up-to-date, 1 failure).
// Output already went to Stdout/Stderr.
func CLI(ctx context.Context, opts Options) int {
	_, err := Run(ctx, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	return 0
}
