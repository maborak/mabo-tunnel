package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maborak/mabo-tunnel/internal/auth"
)

func newAdminTestServer(t *testing.T, adminToken string) *Server {
	t.Helper()
	dir := t.TempDir()
	usersPath := filepath.Join(dir, "users.txt")
	if err := os.WriteFile(usersPath, []byte(auth.HashToken("tok-admin")+":alice:pro\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		Domain:     "tunnel.example.com",
		UsersFile:  usersPath,
		AdminToken: adminToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func doAdmin(s *Server, method, path, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	r.Host = "tunnel.example.com"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestAdminDisabledWithoutToken(t *testing.T) {
	s := newAdminTestServer(t, "")
	for _, path := range []string{"/admin/stats", "/admin/tunnels", "/metrics"} {
		if w := doAdmin(s, http.MethodGet, path, "anything"); w.Code != http.StatusNotFound {
			t.Errorf("%s without --admin-token = %d, want 404", path, w.Code)
		}
	}
}

func TestAdminRequiresCorrectToken(t *testing.T) {
	s := newAdminTestServer(t, "sekrit")
	if w := doAdmin(s, http.MethodGet, "/admin/stats", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", w.Code)
	}
	if w := doAdmin(s, http.MethodGet, "/admin/stats", "wrong"); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong token = %d, want 401", w.Code)
	}
	if w := doAdmin(s, http.MethodGet, "/admin/stats", "sekrit"); w.Code != http.StatusOK {
		t.Errorf("right token = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if w := doAdmin(s, http.MethodGet, "/admin/stats", "sekrit"); !strings.Contains(w.Body.String(), `"users_loaded":1`) {
		t.Errorf("stats body missing users_loaded: %s", w.Body.String())
	}
}

func TestAdminTunnelListAndRevoke(t *testing.T) {
	s := newAdminTestServer(t, "sekrit")
	tm := s.tunnels
	tun, err := tm.Register(RegisterOpts{Conn: testWSConn(t), Username: "alice", Plan: "pro", Subdomain: "live-ui"})
	if err != nil {
		t.Fatal(err)
	}

	w := doAdmin(s, http.MethodGet, "/admin/tunnels", "sekrit")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), tun.ID) {
		t.Fatalf("tunnel list missing tunnel: %d %s", w.Code, w.Body.String())
	}

	if w := doAdmin(s, http.MethodDelete, "/admin/tunnels/"+tun.ID, "sekrit"); w.Code != http.StatusOK {
		t.Fatalf("revoke = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if got := tm.ActiveCount(); got != 0 {
		t.Errorf("active tunnels after revoke = %d, want 0", got)
	}
	if w := doAdmin(s, http.MethodDelete, "/admin/tunnels/"+tun.ID, "sekrit"); w.Code != http.StatusNotFound {
		t.Errorf("double revoke = %d, want 404", w.Code)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	s := newAdminTestServer(t, "sekrit")
	s.metrics.Inc("mabo_auth_attempts_total", "")
	s.metrics.Inc("mabo_auth_failures_total", "")
	s.metrics.Inc("mabo_http_responses_total", statusClass(200))
	s.metrics.Inc("mabo_http_responses_total", statusClass(503))

	w := doAdmin(s, http.MethodGet, "/metrics", "sekrit")
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("metrics = %d, want 200", w.Code)
	}
	for _, want := range []string{
		"# TYPE mabo_tunnels_active gauge",
		"mabo_tunnels_active 0",
		"mabo_users_loaded 1",
		"mabo_auth_attempts_total 1",
		`mabo_http_responses_total{status="2xx"} 1`,
		`mabo_http_responses_total{status="5xx"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q:\n%s", want, body)
		}
	}
}

func TestAdminUsersReload(t *testing.T) {
	s := newAdminTestServer(t, "sekrit")
	usersPath := s.config.UsersFile

	if w := doAdmin(s, http.MethodPost, "/admin/users/reload", "sekrit"); w.Code != http.StatusOK {
		t.Fatalf("reload = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}

	// Add a user, reload, authenticate with it.
	if err := os.WriteFile(usersPath, []byte(auth.HashToken("tok-two")+":bob:free\n"+auth.HashToken("tok-admin")+":alice:pro\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if w := doAdmin(s, http.MethodPost, "/admin/users/reload", "sekrit"); w.Code != http.StatusOK {
		t.Fatalf("reload after edit = %d, want 200", w.Code)
	}
	if _, ok := s.users.Authenticate("tok-two"); !ok {
		t.Error("newly added user did not authenticate after reload")
	}
	if _, ok := s.users.Authenticate("tok-admin"); !ok {
		t.Error("existing user lost after reload")
	}
}

// A broken users file must not evict the working set — the previous users
// stay live until a valid file replaces the broken one.
func TestAdminReloadKeepsPreviousUsersOnParseError(t *testing.T) {
	s := newAdminTestServer(t, "sekrit")
	if err := os.WriteFile(s.config.UsersFile, []byte("not-a-valid-line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if w := doAdmin(s, http.MethodPost, "/admin/users/reload", "sekrit"); w.Code != http.StatusInternalServerError {
		t.Fatalf("reload of broken file = %d, want 500", w.Code)
	}
	if _, ok := s.users.Authenticate("tok-admin"); !ok {
		t.Error("previous users were lost on a failed reload")
	}
}

func TestMetricsRenderNilSafe(t *testing.T) {
	var m *Metrics
	m.Inc("anything", "x")
	m.SetGauge("g", 1)
	if m.Render() != "" {
		t.Error("nil Metrics must render empty")
	}
}
