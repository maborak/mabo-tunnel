package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in     string
		want   Semver
		wantOK bool
	}{
		{"1.2.3", Semver{1, 2, 3, ""}, true},
		{"v1.2.3", Semver{1, 2, 3, ""}, true},
		{"V1.2.3", Semver{1, 2, 3, ""}, true},
		{"1.2", Semver{1, 2, 0, ""}, true},
		{"1", Semver{1, 0, 0, ""}, true},
		{"v1.2.3-rc.1", Semver{1, 2, 3, "rc.1"}, true},
		{"v1.2.3+build.7", Semver{1, 2, 3, ""}, true},
		{" v1.2.3 ", Semver{1, 2, 3, ""}, true},
		// Development builds must NOT parse.
		{"", Semver{}, false},
		{"dev", Semver{}, false},
		{"DEVELOPMENT", Semver{}, false},
		{"7c2859c", Semver{}, false},
		{"7c2859c-dirty", Semver{}, false},
		{"abc", Semver{}, false},
		{"1.2.x", Semver{}, false},
		{"1..3", Semver{}, false},
	}
	for _, c := range cases {
		got, ok := ParseVersion(c.in)
		if ok != c.wantOK {
			t.Errorf("ParseVersion(%q) ok=%v, want %v", c.in, ok, c.wantOK)
			continue
		}
		if ok && got != c.want {
			t.Errorf("ParseVersion(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestCompareVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"v1.0.0", "1.0.0", 0}, // v-prefix is stripped
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"1.1.0", "1.0.9", 1},
		{"2.0.0", "1.99.99", 1},
		{"1.0.0-rc.1", "1.0.0", -1}, // pre-release is older
		{"1.0.0", "1.0.0-rc.1", 1},
		{"1.0.0-rc.1", "1.0.0-rc.2", -1},
		{"1.0.0-rc.1", "0.9.0", 1},
	}
	for _, c := range cases {
		pa, oka := ParseVersion(c.a)
		pb, okb := ParseVersion(c.b)
		if !oka || !okb {
			t.Fatalf("fixture unparsable: %q/%q", c.a, c.b)
		}
		if got := CompareVersion(pa, pb); got != c.want {
			t.Errorf("CompareVersion(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestAssetName(t *testing.T) {
	cases := []struct {
		binary, goos, goarch, want string
	}{
		{"client", "linux", "amd64", "mabo-tunnel-client-linux-amd64"},
		{"server", "darwin", "arm64", "mabo-tunnel-server-darwin-arm64"},
		{"token", "windows", "amd64", "mabo-tunnel-token-windows-amd64.exe"},
	}
	for _, c := range cases {
		if got := AssetName(c.binary, c.goos, c.goarch); got != c.want {
			t.Errorf("AssetName(%q,%q,%q) = %q, want %q", c.binary, c.goos, c.goarch, got, c.want)
		}
	}
}

// TestAssetNamesMatchGoreleaser pins the Go-side asset naming to the exact set
// .goreleaser.yml produces (archives.name_template + windows/arm64 ignore).
// If this test fails after a config change, update BOTH sides together.
func TestAssetNamesMatchGoreleaser(t *testing.T) {
	var want []string
	for _, b := range []string{"server", "client", "token"} {
		for _, os_ := range []string{"linux", "darwin", "windows"} {
			for _, arch := range []string{"amd64", "arm64"} {
				if os_ == "windows" && arch == "arm64" {
					continue // ignored in .goreleaser.yml
				}
				want = append(want, AssetName(b, os_, arch))
			}
		}
	}
	got := goreleaserAssetNames()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("goreleaser contract drifted:\n got: %s\nwant: %s",
			strings.Join(got, ", "), strings.Join(want, ", "))
	}
	if checksumsNm != "SHA256SUMS.txt" {
		t.Errorf("checksums asset name = %q, want SHA256SUMS.txt (goreleaser checksum.name_template)", checksumsNm)
	}
}

// goreleaserAssetNames is the literal binary-asset set .goreleaser.yml emits
// (archives.name_template "mabo-tunnel-{{ .Binary }}-{{ .Os }}-{{ .Arch }}",
// windows/arm64 ignored), byte-for-byte as the YAML spells them. Kept here as
// literals so a config change that breaks the upgrade contract fails the test.
func goreleaserAssetNames() []string {
	return []string{
		"mabo-tunnel-server-linux-amd64",
		"mabo-tunnel-server-linux-arm64",
		"mabo-tunnel-server-darwin-amd64",
		"mabo-tunnel-server-darwin-arm64",
		"mabo-tunnel-server-windows-amd64.exe",
		"mabo-tunnel-client-linux-amd64",
		"mabo-tunnel-client-linux-arm64",
		"mabo-tunnel-client-darwin-amd64",
		"mabo-tunnel-client-darwin-arm64",
		"mabo-tunnel-client-windows-amd64.exe",
		"mabo-tunnel-token-linux-amd64",
		"mabo-tunnel-token-linux-arm64",
		"mabo-tunnel-token-darwin-amd64",
		"mabo-tunnel-token-darwin-arm64",
		"mabo-tunnel-token-windows-amd64.exe",
	}
}

// sha256sums renders a sha256sum-style file for the given name→bytes map.
func sha256sums(files map[string][]byte) []byte {
	var b strings.Builder
	for name, data := range files {
		if name == checksumsNm {
			continue
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	return []byte(b.String())
}

type fakeGH struct {
	srv     *httptest.Server
	apiHits atomic.Int32 // /releases/latest requests
	dlHits  atomic.Int32 // asset downloads
}

// newFakeGH serves a releases/latest JSON plus API-style asset downloads
// (/releases/assets/<id> with octet-stream), mirroring how real asset
// downloads flow through the API host so tokens work on private repos.
func newFakeGH(t *testing.T, tag string, files map[string][]byte) *fakeGH {
	t.Helper()
	fg := &fakeGH{}
	mux := http.NewServeMux()

	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	idByName := make(map[string]int64, len(files))
	next := int64(1001)
	for _, n := range names {
		idByName[n] = next
		next++
	}

	mux.HandleFunc("GET /repos/maborak/mabo-tunnel/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		fg.apiHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"tag_name":%q,"assets":[`, tag)
		for i, n := range names {
			if i > 0 {
				io.WriteString(w, ",")
			}
			fmt.Fprintf(w, `{"id":%d,"name":%q,"size":%d}`, idByName[n], n, len(files[n]))
		}
		io.WriteString(w, `]}`)
	})

	const assetsPrefix = "/repos/maborak/mabo-tunnel/releases/assets/"
	mux.HandleFunc("GET "+assetsPrefix, func(w http.ResponseWriter, r *http.Request) {
		fg.dlHits.Add(1)
		id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, assetsPrefix), 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		for n, want := range idByName {
			if want == id {
				data := files[n]
				w.Header().Set("Content-Length", fmt.Sprint(len(data)))
				_, _ = w.Write(data)
				return
			}
		}
		http.NotFound(w, r)
	})

	fg.srv = httptest.NewServer(mux)
	t.Cleanup(fg.srv.Close)
	return fg
}

// TestRunTruncatedDownload serves a body shorter than its declared size and
// asserts the swap is refused with the original binary intact.
func TestRunTruncatedDownload(t *testing.T) {
	name := AssetName("client", runtime.GOOS, runtime.GOARCH)
	const assetPrefixPath = "/repos/maborak/mabo-tunnel/releases/assets/"
	fg := &fakeGH{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/maborak/mabo-tunnel/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"tag_name":"v1.1.0","assets":[{"id":42,"name":%q,"size":1000}]}`, name)
	})
	mux.HandleFunc("GET "+assetPrefixPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000") // promise more than we send
		_, _ = w.Write([]byte("short body"))
	})
	fg.srv = httptest.NewServer(mux)
	t.Cleanup(fg.srv.Close)

	exe := seedExe(t)
	_, err := Run(context.Background(), Options{
		Binary: "client", Current: "v1.0.0", BaseURL: fg.srv.URL,
		Client: fg.srv.Client(), Target: exe,
		Stdout: io.Discard, Stderr: io.Discard,
	})
	if err == nil {
		t.Fatal("truncated download must fail the upgrade")
	}
	if b, _ := os.ReadFile(exe); string(b) != "OLD BINARY" {
		t.Error("original binary modified on truncated download")
	}
}

// happyFiles returns a complete release payload for the current platform.
func happyFiles(tag string) map[string][]byte {
	name := AssetName("client", runtime.GOOS, runtime.GOARCH)
	payload := []byte("FAKE BINARY PAYLOAD " + tag)
	files := map[string][]byte{name: payload}
	files[checksumsNm] = sha256sums(files)
	return files
}

func TestFetchLatestStatuses(t *testing.T) {
	ctx := context.Background()

	t.Run("404 → ErrNoReleases", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
		srv := httptest.NewServer(mux)
		defer srv.Close()
		gc := newGHClient(srv.URL, srv.Client())
		_, err := gc.fetchLatest(ctx, DefaultOwner, DefaultRepo)
		if !errors.Is(err, ErrNoReleases) {
			t.Fatalf("err = %v, want ErrNoReleases", err)
		}
	})

	t.Run("403 rate limit → ErrRateLimited with reset time", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", fmt.Sprint(time.Now().Add(10*time.Minute).Unix()))
			w.WriteHeader(http.StatusForbidden)
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()
		gc := newGHClient(srv.URL, srv.Client())
		_, err := gc.fetchLatest(ctx, DefaultOwner, DefaultRepo)
		if !errors.Is(err, ErrRateLimited) {
			t.Fatalf("err = %v, want ErrRateLimited", err)
		}
		if !strings.Contains(err.Error(), "resets at") || !strings.Contains(err.Error(), "GH_TOKEN") {
			t.Errorf("error should mention reset time and GH_TOKEN, got: %v", err)
		}
	})

	t.Run("500 → status in message", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()
		gc := newGHClient(srv.URL, srv.Client())
		_, err := gc.fetchLatest(ctx, DefaultOwner, DefaultRepo)
		if err == nil || !strings.Contains(err.Error(), "500") {
			t.Fatalf("err = %v, want status code in message", err)
		}
	})
}

func TestRunUpToDateSkipsDownload(t *testing.T) {
	fg := newFakeGH(t, "v1.0.0", happyFiles("v1.0.0"))
	dir := t.TempDir()
	exe := filepath.Join(dir, "mabo-tunnel-client")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	res, err := Run(context.Background(), Options{
		Binary: "client", Current: "v1.0.0", BaseURL: fg.srv.URL,
		Client: fg.srv.Client(), Target: exe,
		Stdout: io.Discard, Stderr: io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusUpToDate {
		t.Errorf("status = %v, want StatusUpToDate", res.Status)
	}
	if fg.dlHits.Load() != 0 {
		t.Errorf("asset downloaded %d times on up-to-date path, want 0", fg.dlHits.Load())
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Error("up-to-date run modified the binary")
	}
}

func TestRunDevVersionInstallsLatest(t *testing.T) {
	for _, cur := range []string{"dev", "7c2859c-dirty", ""} {
		t.Run("current="+cur, func(t *testing.T) {
			files := happyFiles("v1.0.1")
			fg := newFakeGH(t, "v1.0.1", files)
			exe := seedExe(t)

			res, err := Run(context.Background(), Options{
				Binary: "client", Current: cur, BaseURL: fg.srv.URL,
				Client: fg.srv.Client(), Target: exe,
				Stdout: io.Discard, Stderr: io.Discard,
			})
			if err != nil {
				t.Fatal(err)
			}
			if res.Status != StatusUpdated || res.To != "v1.0.1" {
				t.Errorf("got %+v, want updated to v1.0.1", res)
			}
			assertExeReplaced(t, exe, files)
		})
	}
}

func TestRunSwapsAtomically(t *testing.T) {
	files := happyFiles("v1.1.0")
	fg := newFakeGH(t, "v1.1.0", files)
	exe := seedExe(t)

	res, err := Run(context.Background(), Options{
		Binary: "client", Current: "v1.0.0", BaseURL: fg.srv.URL,
		Client: fg.srv.Client(), Target: exe,
		Stdout: io.Discard, Stderr: io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusUpdated || res.To != "v1.1.0" || res.Path != exe {
		t.Errorf("result = %+v, want updated v1.1.0 at %s", res, exe)
	}
	assertExeReplaced(t, exe, files)
}

func assertExeReplaced(t *testing.T, exe string, files map[string][]byte) {
	t.Helper()
	want := files[AssetName("client", runtime.GOOS, runtime.GOARCH)]
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("binary not replaced: got %d bytes, want %d", len(got), len(want))
	}
	fi, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("exec bit lost: perm = %o", fi.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(exe))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "."+assetPrefix+"-upgrade-") {
			t.Errorf("temp leftover left behind: %s", e.Name())
		}
	}
}

func seedExe(t *testing.T) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "mabo-tunnel-client")
	if err := os.WriteFile(exe, []byte("OLD BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	return exe
}

// failureCase wraps the scenarios where the swap must NOT happen and the
// original binary must stay byte-for-byte intact.
func TestRunFailuresLeaveOriginalIntact(t *testing.T) {
	base := happyFiles("v1.1.0")
	assetName := AssetName("client", runtime.GOOS, runtime.GOARCH)

	cases := []struct {
		name      string
		files     map[string][]byte
		errSubstr string
	}{
		{
			name: "checksum mismatch",
			files: func() map[string][]byte {
				f := map[string][]byte{assetName: base[assetName]}
				f[checksumsNm] = sha256sums(map[string][]byte{assetName: []byte("totally different bytes")})
				return f
			}(),
			errSubstr: "checksum mismatch",
		},
		{
			name: "no checksum entry",
			files: func() map[string][]byte {
				f := map[string][]byte{assetName: base[assetName]}
				f[checksumsNm] = []byte("# comment line only\n")
				return f
			}(),
			errSubstr: "no entry",
		},
		{
			name:      "missing sums asset",
			files:     map[string][]byte{assetName: base[assetName]},
			errSubstr: "SHA256SUMS.txt",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fg := newFakeGH(t, "v1.1.0", tc.files)
			exe := seedExe(t)

			_, err := Run(context.Background(), Options{
				Binary: "client", Current: "v1.0.0", BaseURL: fg.srv.URL,
				Client: fg.srv.Client(), Target: exe,
				Stdout: io.Discard, Stderr: io.Discard,
			})
			if err == nil || !strings.Contains(err.Error(), tc.errSubstr) {
				t.Fatalf("err = %v, want substring %q", err, tc.errSubstr)
			}
			if b, _ := os.ReadFile(exe); string(b) != "OLD BINARY" {
				t.Error("original binary was modified on failure path")
			}
			for _, e := range mustReadDir(t, filepath.Dir(exe)) {
				if strings.HasPrefix(e, "."+assetPrefix+"-upgrade-") {
					t.Errorf("temp leftover: %s", e)
				}
			}
		})
	}
}

func TestRunMissingAssetForPlatform(t *testing.T) {
	// Release only carries linux/amd64 — any other platform must get the
	// typed error without downloading anything.
	files := map[string][]byte{
		"mabo-tunnel-client-linux-amd64": []byte("payload"),
		checksumsNm:                      []byte("deadbeef  mabo-tunnel-client-linux-amd64\n"),
	}
	fg := newFakeGH(t, "v1.1.0", files)
	exe := seedExe(t)

	_, err := Run(context.Background(), Options{
		Binary: "client", Current: "v1.0.0", BaseURL: fg.srv.URL,
		Client: fg.srv.Client(), Target: exe,
		Stdout: io.Discard, Stderr: io.Discard,
	})
	if !errors.Is(err, ErrUnsupportedPlatform) && !strings.Contains(err.Error(), "need asset") {
		t.Fatalf("err = %v, want unsupported-platform error naming the asset", err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "OLD BINARY" {
		t.Error("original binary modified")
	}
}

func TestRunForceReinstallsWhenEqual(t *testing.T) {
	files := happyFiles("v1.0.0")
	fg := newFakeGH(t, "v1.0.0", files)
	exe := seedExe(t)

	res, err := Run(context.Background(), Options{
		Binary: "client", Current: "v1.0.0", Force: true, BaseURL: fg.srv.URL,
		Client: fg.srv.Client(), Target: exe,
		Stdout: io.Discard, Stderr: io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusUpdated {
		t.Errorf("force run status = %v, want StatusUpdated", res.Status)
	}
	assertExeReplaced(t, exe, files)
}

func mustReadDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}
