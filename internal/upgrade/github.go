package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultOwner and DefaultRepo are the GitHub coordinates this binary
	// self-updates from. Both entrypoints reference these; do not repeat the
	// strings in cmd/.
	DefaultOwner = "maborak"
	DefaultRepo  = "mabo-tunnel"

	// assetPrefix is the release-asset naming stem. It mirrors the
	// archives.name_template in .goreleaser.yml exactly — a golden test pins
	// the two together.
	assetPrefix = "mabo-tunnel"

	// maxBinaryBytes caps a downloaded binary so a bad release asset cannot
	// fill a disk.
	maxBinaryBytes = 512 << 20

	apiTimeout  = 30 * time.Second
	dlTimeout   = 10 * time.Minute
	checksumsNm = "SHA256SUMS.txt"
)

var (
	// ErrNoReleases means the repo has no published release yet.
	ErrNoReleases = errors.New("no published releases found")
	// ErrRateLimited means GitHub's unauthenticated API quota (60 req/hr per
	// IP) is exhausted. Set GH_TOKEN to raise it to 5000/hr.
	ErrRateLimited = errors.New("github API rate limit exceeded")
	// ErrUnsupportedPlatform means the release has no asset for this
	// GOOS/GOARCH.
	ErrUnsupportedPlatform = errors.New("no release asset for this platform")
)

type ghAsset struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

// ghClient talks to one GitHub API host. Assets are downloaded through the
// API's octet-stream endpoint rather than browser_download_url: the browser
// URL 404s for private repos without an interactive session, while the API
// endpoint honors a bearer token (and works anonymously for public ones).
type ghClient struct {
	base string // e.g. https://api.github.com (override for tests)
	hc   *http.Client
}

func newGHClient(baseURL string, hc *http.Client) *ghClient {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	if hc == nil {
		hc = &http.Client{Timeout: apiTimeout}
	}
	return &ghClient{base: strings.TrimSuffix(baseURL, "/"), hc: hc}
}

func (g *ghClient) token() string {
	tok := os.Getenv("GH_TOKEN")
	if tok == "" {
		tok = os.Getenv("GITHUB_TOKEN")
	}
	return tok
}

// do performs an authenticated GET against the API host. The returned cancel
// MUST be called only after the response body has been fully consumed —
// canceling earlier aborts the in-flight body read.
func (g *ghClient) do(ctx context.Context, path, accept string, timeout time.Duration) (*http.Response, func(), error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, g.base+path, nil)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	req.Header.Set("Accept", accept)
	if tok := g.token(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := g.hc.Do(req)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return resp, cancel, nil
}

// fetchLatest GETs /releases/latest for owner/repo.
func (g *ghClient) fetchLatest(ctx context.Context, owner, repo string) (*ghRelease, error) {
	resp, cancel, err := g.do(ctx, "/repos/"+owner+"/"+repo+"/releases/latest", "application/vnd.github+json", apiTimeout)
	if err != nil {
		return nil, fmt.Errorf("contact github: %w", err)
	}
	defer cancel()
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// fall through to decode
	case http.StatusNotFound:
		return nil, fmt.Errorf("%w (https://github.com/%s/%s/releases)", ErrNoReleases, owner, repo)
	case http.StatusForbidden:
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			detail := ""
			if reset, perr := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); perr == nil {
				detail += fmt.Sprintf(" — resets at %s", time.Unix(reset, 0).Local().Format("15:04"))
			}
			detail += " (set GH_TOKEN to raise the limit)"
			return nil, fmt.Errorf("%w%s", ErrRateLimited, detail)
		}
		fallthrough
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("github API returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}
	return &rel, nil
}

// findAsset returns the named asset from the release.
func findAsset(rel *ghRelease, name string) (*ghAsset, error) {
	for i := range rel.Assets {
		if rel.Assets[i].Name == name {
			return &rel.Assets[i], nil
		}
	}
	return nil, ErrUnsupportedPlatform
}

// parseChecksums decodes a sha256sum-style file ("<hex><ws>*<name>" per line)
// into name → hex. The leading "*" (binary-mode marker) is stripped.
func parseChecksums(data []byte) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		out[name] = strings.ToLower(fields[0])
	}
	return out
}

// download streams the given asset into dst, verifying size and sha256 against
// the release's SHA256SUMS.txt. On any failure the error explains what went
// wrong; the original binary on disk is never touched here.
func (g *ghClient) download(ctx context.Context, owner, repo string, rel *ghRelease, name string, dst io.Writer) error {
	a, err := findAsset(rel, name)
	if err != nil {
		return err
	}
	if a.Size > maxBinaryBytes {
		return fmt.Errorf("asset %s is %d bytes (limit %d) — refusing", name, a.Size, int64(maxBinaryBytes))
	}
	if a.ID == 0 {
		return fmt.Errorf("asset %s has no API id (cannot download)", name)
	}

	path := "/repos/" + owner + "/" + repo + "/releases/assets/" + strconv.FormatInt(a.ID, 10)
	resp, cancel, err := g.do(ctx, path, "application/octet-stream", dlTimeout)
	if err != nil {
		return fmt.Errorf("download %s: %w", name, err)
	}
	defer cancel()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: server returned %s", name, resp.Status)
	}

	hasher := sha256.New()
	n, err := io.Copy(dst, io.TeeReader(io.LimitReader(resp.Body, a.Size+1), hasher))
	if err != nil {
		return fmt.Errorf("download %s: %w", name, err)
	}
	if n != a.Size {
		return fmt.Errorf("download %s incomplete: got %d of %d bytes", name, n, a.Size)
	}

	sums, err := g.fetchChecksums(ctx, owner, repo, rel)
	if err != nil {
		return err
	}
	want, ok := sums[name]
	if !ok {
		return fmt.Errorf("checksums list has no entry for %s", name)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != want {
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", name, got, want)
	}
	return nil
}

// fetchChecksums downloads and parses SHA256SUMS.txt from the release.
func (g *ghClient) fetchChecksums(ctx context.Context, owner, repo string, rel *ghRelease) (map[string]string, error) {
	a, err := findAsset(rel, checksumsNm)
	if err != nil {
		return nil, fmt.Errorf("release has no %s asset", checksumsNm)
	}
	if a.ID == 0 {
		return nil, fmt.Errorf("asset %s has no API id (cannot download)", checksumsNm)
	}

	path := "/repos/" + owner + "/" + repo + "/releases/assets/" + strconv.FormatInt(a.ID, 10)
	resp, cancel, err := g.do(ctx, path, "application/octet-stream", apiTimeout)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", checksumsNm, err)
	}
	defer cancel()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: server returned %s", checksumsNm, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", checksumsNm, err)
	}
	sums := parseChecksums(data)
	if len(sums) == 0 {
		return nil, fmt.Errorf("%s is empty or malformed", checksumsNm)
	}
	return sums, nil
}
