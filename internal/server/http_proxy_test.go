package server

import (
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/maborak/mabo-tunnel/internal/protocol"
)

// netPipe returns a connected pair of sockets over loopback.
func netPipe(t *testing.T) (server, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server = <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	return server, client
}

func testProxyHandler(t *testing.T, trusted []string) *ProxyHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewProxyHandler(nil, "mabo-tunnel.test", trusted, 0, logger)
}

// The IP allow and deny lists are only meaningful if the address they compare
// against cannot be chosen by the caller.
func TestExtractClientIPIgnoresForwardedHeaderFromUntrustedPeer(t *testing.T) {
	p := testProxyHandler(t, []string{"10.0.0.0/8"})

	r := httptest.NewRequest("GET", "http://tunnel.mabo-tunnel.test/", nil)
	r.RemoteAddr = "203.0.113.9:44321" // public address, not a trusted hop
	r.Header.Set("X-Forwarded-For", "192.0.2.55")

	if got := p.extractClientIP(r); got != "203.0.113.9" {
		t.Errorf("extractClientIP = %q, want the peer address 203.0.113.9 — a caller must not be able to name itself", got)
	}
}

func TestExtractClientIPHonorsForwardedHeaderFromTrustedProxy(t *testing.T) {
	p := testProxyHandler(t, []string{"10.0.0.0/8"})

	r := httptest.NewRequest("GET", "http://tunnel.mabo-tunnel.test/", nil)
	r.RemoteAddr = "10.1.2.3:5000" // the reverse proxy
	r.Header.Set("X-Forwarded-For", "198.51.100.7")

	if got := p.extractClientIP(r); got != "198.51.100.7" {
		t.Errorf("extractClientIP = %q, want 198.51.100.7", got)
	}
}

// With a chain, the rightmost address that is not itself a trusted hop is the
// closest thing to a real client. Taking the leftmost lets a caller prepend
// whatever it likes.
func TestExtractClientIPWalksChainFromTheRight(t *testing.T) {
	p := testProxyHandler(t, []string{"10.0.0.0/8"})

	r := httptest.NewRequest("GET", "http://tunnel.mabo-tunnel.test/", nil)
	r.RemoteAddr = "10.1.2.3:5000"
	// The caller forged the first entry; 198.51.100.7 is what the proxy saw.
	r.Header.Set("X-Forwarded-For", "192.0.2.55, 198.51.100.7, 10.9.9.9")

	if got := p.extractClientIP(r); got != "198.51.100.7" {
		t.Errorf("extractClientIP = %q, want 198.51.100.7 (forged leading entry must be ignored)", got)
	}
}

func TestExtractClientIPFallsBackWhenChainIsAllTrusted(t *testing.T) {
	p := testProxyHandler(t, []string{"10.0.0.0/8"})

	r := httptest.NewRequest("GET", "http://tunnel.mabo-tunnel.test/", nil)
	r.RemoteAddr = "10.1.2.3:5000"
	r.Header.Set("X-Forwarded-For", "10.4.4.4, 10.5.5.5")

	if got := p.extractClientIP(r); got != "10.1.2.3" {
		t.Errorf("extractClientIP = %q, want 10.1.2.3", got)
	}
}

func TestCheckIPAccessCannotBeBypassedWithHeader(t *testing.T) {
	p := testProxyHandler(t, []string{"10.0.0.0/8"})
	tunnel := &Tunnel{ID: "t1"}
	tunnel.SetIPFilters([]string{"198.51.100.7"}, nil)

	r := httptest.NewRequest("GET", "http://tunnel.mabo-tunnel.test/", nil)
	r.RemoteAddr = "203.0.113.9:44321"
	r.Header.Set("X-Forwarded-For", "198.51.100.7") // claiming to be the allowed address

	if p.checkIPAccess(r, tunnel) {
		t.Error("an untrusted caller passed the allow list by sending X-Forwarded-For")
	}
}

// The same address has several textual forms; a deny entry that only matches
// one of them is a deny entry a caller walks through by re-encoding.
func TestCheckIPAccessDenyListMatchesIPv4MappedIPv6(t *testing.T) {
	p := testProxyHandler(t, []string{"10.0.0.0/8"})
	tunnel := &Tunnel{ID: "t1"}
	tunnel.SetIPFilters(nil, []string{"6.6.6.6"})

	r := httptest.NewRequest("GET", "http://tunnel.mabo-tunnel.test/", nil)
	r.RemoteAddr = "10.1.2.3:5000" // trusted reverse proxy
	r.Header.Set("X-Forwarded-For", "::ffff:6.6.6.6")

	if p.checkIPAccess(r, tunnel) {
		t.Error("deny entry 6.6.6.6 was bypassed with its IPv4-mapped IPv6 form")
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"6.6.6.6", "6.6.6.6"},
		{"::ffff:6.6.6.6", "6.6.6.6"},
		{" 6.6.6.6 ", "6.6.6.6"},
		{"2001:db8::1", "2001:db8::1"},
		{"2001:0db8:0000::1", "2001:db8::1"},
		{"not-an-ip", "not-an-ip"}, // unchanged: allow lists fail closed on it
	}
	for _, tc := range cases {
		ip := net.ParseIP(strings.TrimSpace(tc.in))
		got := tc.in
		if ip != nil {
			if v4 := ip.To4(); v4 != nil {
				got = v4.String()
			} else {
				got = ip.String()
			}
		}
		if got != tc.want {
			t.Errorf("canonical IP(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A tunnel peer must not dictate edge-connection semantics: hop-by-hop
// headers, anything its Connection header names, and its asserted
// Content-Length stay behind. The public response is framed from the bytes
// actually forwarded.
func TestCopyResponseHeadersStripsHopByHopAndContentLength(t *testing.T) {
	rec := httptest.NewRecorder()
	headers := map[string][]string{
		"Connection":        {"close, X-Per-Conn"},
		"X-Per-Conn":        {"must-not-cross"},
		"Keep-Alive":        {"timeout=5"},
		"Transfer-Encoding": {"chunked"},
		"Content-Length":    {"3"},
		"X-Good":            {"passes"},
		"connection":        {"also-stripped-noncanonical"},
	}

	copyResponseHeaders(rec, headers)
	rec.WriteHeader(200)

	got := rec.Header()
	if _, ok := got["X-Good"]; !ok {
		t.Error("end-to-end header X-Good was stripped")
	}
	for _, hop := range []string{"X-Per-Conn", "Keep-Alive", "Transfer-Encoding", "Content-Length", "Connection"} {
		if _, ok := got[hop]; ok {
			t.Errorf("hop-by-hop header %q crossed the proxy boundary", hop)
		}
	}
}

func TestExtractSubdomain(t *testing.T) {
	p := testProxyHandler(t, nil)

	cases := []struct {
		host string
		want string
	}{
		{"abc.mabo-tunnel.test", "abc"},
		{"abc.mabo-tunnel.test:8080", "abc"},
		{"mabo-tunnel.test", ""},
		{"abc.def.mabo-tunnel.test", ""},
		{"abc.example.com", ""},
		{"[::1]:8080", ""},
		{"", ""},
	}

	for _, tc := range cases {
		if got := p.extractSubdomain(tc.host); got != tc.want {
			t.Errorf("extractSubdomain(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

func TestHostWithoutPort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com:8080", "example.com"},
		{"example.com", "example.com"},
		{"127.0.0.1:80", "127.0.0.1"},
		{"[::1]:8080", "::1"},
		{"[::1]", "::1"},
	}
	for _, tc := range cases {
		if got := hostWithoutPort(tc.in); got != tc.want {
			t.Errorf("hostWithoutPort(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A response whose events were dropped must not end cleanly, or the caller
// reads a truncated body under a success status.
func TestProxiedConnRecordsOverflow(t *testing.T) {
	pc := NewProxiedConn("c1", nil)

	if !pc.PushHeader(&protocol.RespHeaderFrame{ConnID: "c1", StatusCode: 200}) {
		t.Fatal("first push should succeed")
	}
	// Fill the buffer past capacity.
	overflowed := false
	for i := 0; i < proxiedConnBuffer+10; i++ {
		if !pc.PushBody([]byte("chunk")) {
			overflowed = true
			break
		}
	}

	if !overflowed {
		t.Fatal("expected the event buffer to overflow")
	}
	if !pc.Overflowed() {
		t.Error("Overflowed() = false after chunks were dropped")
	}
}

func TestStreamingConnClosesOnOverflow(t *testing.T) {
	sc := &StreamingConn{
		ID:      "s1",
		DataCh:  make(chan []byte, 2),
		CloseCh: make(chan struct{}),
	}

	if !sc.TrySend([]byte("a")) || !sc.TrySend([]byte("b")) {
		t.Fatal("sends within capacity should succeed")
	}
	if sc.TrySend([]byte("c")) {
		t.Fatal("send past capacity should fail")
	}

	select {
	case <-sc.CloseCh:
		// Correct: a hole in a byte stream ends the connection.
	default:
		t.Error("connection stayed open after a chunk was dropped")
	}
}

func TestConnWriterPreservesOrder(t *testing.T) {
	server, client := netPipe(t)
	defer server.Close()
	defer client.Close()

	w := newConnWriter(server)
	defer w.Close()

	const n = 50
	for i := 0; i < n; i++ {
		if !w.Send([]byte{byte(i)}) {
			t.Fatalf("send %d failed", i)
		}
	}

	got := make([]byte, n)
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	for i := 0; i < n; i++ {
		if got[i] != byte(i) {
			t.Fatalf("byte %d = %d, want %d — writes were reordered", i, got[i], i)
		}
	}
}
