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
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

// apiClient returns the HTTP client to use, defaulting sensibly.
func apiClient(hc *http.Client) *http.Client {
	if hc != nil {
		return hc
	}
	return &http.Client{Timeout: apiTimeout}
}

func decodeJSON(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}

// fetchLatest GETs /releases/latest for owner/repo against baseURL (override
// for tests). An optional GH_TOKEN or GITHUB_TOKEN env var is sent as a bearer
// token to lift the unauthenticated rate limit.
func fetchLatest(ctx context.Context, baseURL, owner, repo string, hc *http.Client) (*ghRelease, error) {
	c := apiClient(hc)
	reqCtx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()

	url := strings.TrimSuffix(baseURL, "/") + "/repos/" + owner + "/" + repo + "/releases/latest"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	tok := os.Getenv("GH_TOKEN")
	if tok == "" {
		tok = os.Getenv("GITHUB_TOKEN")
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("contact github: %w", err)
	}
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
	if err := decodeJSON(resp.Body, &rel); err != nil {
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

// downloadAsset streams the named asset into dst, verifying size and sha256.
// On any failure dst is left for the caller's cleanup and the error explains
// what went wrong; the original binary on disk is never touched here.
func downloadAsset(ctx context.Context, rel *ghRelease, name string, dst io.Writer, hc *http.Client) error {
	a, err := findAsset(rel, name)
	if err != nil {
		return err
	}
	if a.Size > maxBinaryBytes {
		return fmt.Errorf("asset %s is %d bytes (limit %d) — refusing", name, a.Size, int64(maxBinaryBytes))
	}

	// Shallow-copy so the caller's client (and its Transport for tests) is
	// preserved while the download gets the longer timeout.
	dc := *apiClient(hc)
	dc.Timeout = dlTimeout
	c := &dc
	reqCtx, cancel := context.WithTimeout(ctx, dlTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, a.BrowserDownloadURL, nil)
	if err != nil {
		return fmt.Errorf("build download request: %w", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", name, err)
	}
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

	sums, err := fetchChecksums(ctx, rel, hc)
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
func fetchChecksums(ctx context.Context, rel *ghRelease, hc *http.Client) (map[string]string, error) {
	a, err := findAsset(rel, checksumsNm)
	if err != nil {
		return nil, fmt.Errorf("release has no %s asset", checksumsNm)
	}
	c := apiClient(hc)
	reqCtx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, a.BrowserDownloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build checksum request: %w", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", checksumsNm, err)
	}
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
