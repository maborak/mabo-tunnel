package client

import (
	"strings"
	"testing"

	"github.com/maborak/mabo-tunnel/internal/protocol"
)

// The server assigns a fresh tunnel ID per connection, so a reconnecting
// client calls AddTunnel repeatedly for the same configured tunnel. The
// dashboard must reuse the entry, not grow one per reconnect.
func TestAddTunnelDedupesOnReconnect(t *testing.T) {
	ld := NewLocalDashboard(NewInspector())

	ld.AddTunnel("id-1", "http://aaa.mabo-tunnel.test", 3000, "ui")
	ld.AddTunnel("id-2", "http://aaa.mabo-tunnel.test", 3000, "ui")
	ld.AddTunnel("id-3", "http://bbb.mabo-tunnel.test", 9001, "api")

	ld.mu.RLock()
	defer ld.mu.RUnlock()
	if len(ld.tunnels) != 2 {
		t.Fatalf("tunnel entries = %d, want 2 (reconnect must reuse, not append)", len(ld.tunnels))
	}
	for _, tn := range ld.tunnels {
		if tn.LocalPort == 3000 && tn.ID != "id-2" {
			t.Errorf("port-3000 entry kept stale ID %q, want id-2", tn.ID)
		}
	}
}

// Captured history must follow the tunnel across reconnects: the old ID's
// ring buffer becomes the new ID's, and nothing is left stranded under an ID
// no route resolves anymore.
func TestReassignTunnelMigratesHistory(t *testing.T) {
	insp := NewInspector()

	insp.RecordFull(&CapturedRequest{TunnelID: "id-1", Method: "GET", Path: "/first"})
	insp.RecordFull(&CapturedRequest{TunnelID: "id-1", Method: "POST", Path: "/second"})

	// A record already exists under the new ID (traffic on the new tunnel).
	insp.RecordFull(&CapturedRequest{TunnelID: "id-2", Method: "GET", Path: "/after-reconnect"})

	insp.ReassignTunnel("id-1", "id-2")

	if got := insp.RequestCount("id-1"); got != 0 {
		t.Errorf("old ID still holds %d captured requests — the leak the migration exists to stop", got)
	}
	reqs := insp.GetRequests("id-2")
	if len(reqs) != 3 {
		t.Fatalf("new ID holds %d requests, want 3 (2 migrated + 1 native)", len(reqs))
	}
	if reqs[0].Path != "/first" || reqs[2].Path != "/after-reconnect" {
		t.Errorf("migration lost ordering: %q, %q, %q", reqs[0].Path, reqs[1].Path, reqs[2].Path)
	}

	// The ring cap still applies to the merged buffer.
	for i := 0; i < maxRequestsPerTunnel+10; i++ {
		insp.RecordFull(&CapturedRequest{TunnelID: "id-2", Method: "GET", Path: "/fill"})
	}
	if got := insp.RequestCount("id-2"); got != maxRequestsPerTunnel {
		t.Errorf("merged ring holds %d, want capped at %d", got, maxRequestsPerTunnel)
	}
}

// Frame payload limits are the client's defense against a hostile or broken
// server: an oversize frame tears down the connection instead of parking
// megabytes in queues sized for the documented chunk sizes.
func TestCheckFrameSize(t *testing.T) {
	if err := checkFrameSize("req_body", make([]byte, protocol.MaxStreamChunkBytes)); err != nil {
		t.Errorf("chunk at the limit rejected: %v", err)
	}
	if err := checkFrameSize("req_body", make([]byte, protocol.MaxStreamChunkBytes+1)); err == nil {
		t.Error("oversize req_body accepted")
	}
	if err := checkFrameSize("data", make([]byte, protocol.MaxRequestHeadBytes)); err != nil {
		t.Errorf("request head at the limit rejected: %v", err)
	}
	if err := checkFrameSize("data", make([]byte, protocol.MaxRequestHeadBytes+1)); err == nil {
		t.Error("oversize data frame accepted")
	}
}

// The "copy as cURL/wget/fetch" builders interpolate attacker-controlled
// request data into strings a developer pastes into a terminal or console.
// Every interpolation must go through shellQuote / jsLiteral — a builder
// that interpolates a raw value is command injection on the developer's
// machine. This pins the escaping against regressions; the behavior itself
// was verified by executing the shipped functions against hostile inputs.
func TestDashboardBuildersQuoteAllInterpolations(t *testing.T) {
	js := string(dashboardHTML)
	if !strings.Contains(js, "function shellQuote") || !strings.Contains(js, "function jsLiteral") {
		t.Fatal("escaping helpers missing from dashboard")
	}
	for _, builder := range []string{"buildCurl", "buildWget"} {
		body := extractJSFunction(js, builder)
		if body == "" {
			t.Fatalf("%s not found in dashboard", builder)
		}
		if strings.Contains(body, "${req.request_headers}") || strings.Contains(body, "header='${") {
			t.Errorf("%s interpolates unescaped header values", builder)
		}
		if strings.Contains(body, "'${url}'") || strings.Contains(body, "${shellQuote(url)}") == false {
			t.Errorf("%s does not shell-quote the URL", builder)
		}
	}
	body := extractJSFunction(js, "buildFetch")
	if body == "" {
		t.Fatal("buildFetch not found in dashboard")
	}
	if strings.Contains(body, "fetch('${url}'") {
		t.Error("buildFetch interpolates the URL into a raw string literal")
	}
}

// extractJSFunction returns the source of a named function from the embedded
// dashboard script, or "" if absent.
func extractJSFunction(src, name string) string {
	start := strings.Index(src, "function "+name+"(")
	if start < 0 {
		return ""
	}
	depth := 0
	for i := start; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[start : i+1]
			}
		}
	}
	return src[start:]
}
