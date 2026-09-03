package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libdns/libdns"

	"github.com/maborak/mabo-tunnel/internal/auth"
	"github.com/maborak/mabo-tunnel/internal/protocol"
)

// tokenHashHex mirrors what the server stores: sha256(token), hex encoded.
func tokenHashHex(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func TestCustomDomainChallengeDeterministic(t *testing.T) {
	th := tokenHashHex("my-token")
	a := protocol.CustomDomainChallenge(th, "app.apps.example.com")
	b := protocol.CustomDomainChallenge(th, "APP.Apps.Example.com.")
	if a != b {
		t.Errorf("challenge must be case/trailing-dot insensitive: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "") || len(a) != 64 {
		t.Errorf("challenge should be a 64-char hex digest, got %q", a)
	}
}

func TestIsHostname(t *testing.T) {
	for _, ok := range []string{"a.b.c", "app.apps.example.com", "x-y.example.com"} {
		if !isHostname(ok) {
			t.Errorf("%q should be a valid hostname", ok)
		}
	}
	for _, bad := range []string{"", "-a.example.com", "a-.example.com", "a_b.example.com", strings.Repeat("a", 64), "not a host"} {
		if isHostname(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

// fakeDNSReader serves preloaded TXT records for verifyCustomDomain.
type fakeDNSReader struct {
	records map[string][]libdns.Record
	err     error
}

func (f *fakeDNSReader) GetRecords(_ context.Context, zone string) ([]libdns.Record, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.records[zone], nil
}

func newCustomTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	usersPath := filepath.Join(dir, "users.txt")
	if err := os.WriteFile(usersPath, []byte(auth.HashToken("tok-custom")+":alice:pro\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		Domain:        "tunnel.example.com",
		UsersFile:     usersPath,
		CustomDomains: []string{"apps.customer-zone.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func TestVerifyCustomDomainViaProviderLookup(t *testing.T) {
	s := newCustomTestServer(t)
	th := tokenHashHex("tok-custom")
	domain := "alice.apps.customer-zone.test"

	expected := protocol.CustomDomainChallenge(th, domain)
	fqdn := "_mabo-challenge." + domain

	wrongRecord := libdns.TXT{Name: fqdn, Text: "deadbeef"}
	rightRecord := libdns.TXT{Name: fqdn, Text: expected}

	reader := &fakeDNSReader{records: make(map[string][]libdns.Record)}
	s.dnsReader = reader

	if err := s.verifyCustomDomain(t.Context(), th, domain); err == nil {
		t.Fatal("verification must fail without the TXT record present")
	}
	reader.records["apps.customer-zone.test"] = []libdns.Record{wrongRecord}
	if err := s.verifyCustomDomain(t.Context(), th, domain); err == nil {
		t.Fatal("wrong TXT value must not verify")
	}
	reader.records["apps.customer-zone.test"] = []libdns.Record{rightRecord}
	if err := s.verifyCustomDomain(t.Context(), th, domain); err != nil {
		t.Fatalf("correct TXT value should verify: %v", err)
	}

	for _, bad := range []string{"outside.zone.test", "tunnel.example.com", "bad..name", "sub.tunnel.example.com"} {
		if err := s.verifyCustomDomain(t.Context(), th, bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestVerifyCustomDomainDisabled(t *testing.T) {
	s := newAdminTestServer(t, "")
	if err := s.verifyCustomDomain(t.Context(), "aa", "x.y.z"); err == nil {
		t.Error("custom domains must be rejected when not configured")
	}
}

func TestManagerClaimsAndReleasesCustomHost(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tm := NewTunnelManager("tunnel.example.com", 10000, 10100, logger)

	t1, err := tm.Register(RegisterOpts{
		Conn: testWSConn(t), Username: "alice", Plan: "pro",
		CustomDomain: "ALICE.apps.x.test.", SessionID: "s1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if t1.CustomHost != "alice.apps.x.test" {
		t.Errorf("custom host not normalized: %q", t1.CustomHost)
	}
	if _, ok := tm.LookupCustom("alice.apps.x.test"); !ok {
		t.Fatal("custom lookup failed after registration")
	}

	if _, err := tm.Register(RegisterOpts{
		Conn: testWSConn(t), Username: "mallory", Plan: "pro",
		CustomDomain: "alice.apps.x.test", SessionID: "s2",
	}); err == nil {
		t.Fatal("second user claimed an occupied custom domain")
	}

	t2, err := tm.Register(RegisterOpts{
		Conn: testWSConn(t), Username: "alice", Plan: "pro",
		CustomDomain: "alice.apps.x.test", SessionID: "s1",
	})
	if err != nil {
		t.Fatalf("same-session reclaim failed: %v", err)
	}
	if got := tm.ActiveCount(); got != 1 {
		t.Errorf("active tunnels after reclaim = %d, want 1", got)
	}

	tm.Unregister(t2.ID)
	if _, ok := tm.LookupCustom("alice.apps.x.test"); ok {
		t.Fatal("custom host was not released on unregister")
	}
}
