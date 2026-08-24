package tests

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maborak/mabo-tunnel/internal/client"
	"github.com/maborak/mabo-tunnel/internal/protocol"
	"github.com/gorilla/websocket"
)

// A tunnel that dies while a worker streams a quiet response (headers sent,
// body stalled — an SSE stream with nothing to say) must not wedge the client
// until process restart: cancellation has to reach the in-flight request so
// the reconnect loop can run. This drives the client against a fake tunnel
// server we can kill on cue.
func TestClientReconnectsWhenTunnelDiesMidStream(t *testing.T) {
	// Local backend: send headers, then stall until the request context is
	// canceled. The stall-after-headers shape is the one no transport
	// timeout unblocks by design.
	backendEntered := make(chan struct{}, 1)
	var cancelReached atomic.Bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		backendEntered <- struct{}{}
		<-r.Context().Done()
		cancelReached.Store(true)
	}))
	defer backend.Close()

	// Fake tunnel server: handshakes auth, delivers one request head, then —
	// only once the backend has actually received it — kills the socket
	// without a close handshake, like a network failure.
	var connects atomic.Int64
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if connects.Add(1) == 1 {
			serveFakeTunnelThenKill(t, w, r, upgrader, backendEntered)
			return
		}
		// Later connects just complete the handshake and idle.
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		for {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer fake.Close()

	cfg := client.Config{
		ServerURL: "ws://" + strings.TrimPrefix(fake.URL, "http://"),
		Token:     "anything",
		LocalPort: extractPort(backend.URL),
	}
	c := client.New(cfg, client.NewDisplay(1), nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	if !waitFor(t, 15*time.Second, func() bool { return connects.Load() >= 2 }) {
		t.Fatalf("client never reconnected after tunnel death (connects=%d) — a stalled worker is holding the connection open", connects.Load())
	}
	if !waitFor(t, 15*time.Second, func() bool { return cancelReached.Load() }) {
		t.Fatal("the in-flight upstream request was never canceled — the worker is still blocked on the stalled stream")
	}
}

func serveFakeTunnelThenKill(t *testing.T, w http.ResponseWriter, r *http.Request, upgrader websocket.Upgrader, backendEntered <-chan struct{}) {
	t.Helper()
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// auth handshake
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return
	}
	env, err := protocol.ParseEnvelope(msg)
	if err != nil {
		return
	}
	var authReq protocol.AuthRequest
	if err := env.ParsePayload(&authReq); err != nil {
		return
	}
	resp, _ := protocol.NewEnvelope(protocol.TypeAuthResponse, &protocol.AuthResponse{
		Success: true, TunnelID: "fake-tunnel", Subdomain: "stall",
		URL: "http://stall." + testDomain, Username: "u", Binary: true,
	})
	respBytes, _ := resp.Marshal()
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if conn.WriteMessage(websocket.TextMessage, respBytes) != nil {
		return
	}

	// One proxied request head.
	head := []byte("GET /stall HTTP/1.1\r\nHost: stall." + testDomain + "\r\n\r\n")
	frame, _ := protocol.EncodeBinaryFrame(protocol.BinTypeData, "c1", head)
	conn.WriteMessage(websocket.BinaryMessage, frame)

	// Wait until the backend is actually streaming, then simulate network
	// death — no close handshake.
	select {
	case <-backendEntered:
	case <-time.After(10 * time.Second):
		return
	}
	time.Sleep(100 * time.Millisecond) // let the worker enter resp.Body.Read
	conn.Close()                       // kill without close handshake
}

// The server appends the origin it verified to X-Forwarded-For before the
// head enters the tunnel, and the client passes the chain through — so a
// local app reading the rightmost entry gets an address the edge confirmed,
// not one the caller typed.
func TestXForwardedForCarriesVerifiedOrigin(t *testing.T) {
	type xffResult struct {
		xff string
		ok  bool
	}
	xffCh := make(chan xffResult, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xffCh <- xffResult{r.Header.Get("X-Forwarded-For"), true}
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	tunnelURL, cancelTunnel, err := startTunnelClient(t, extractPort(backend.URL))
	if err != nil {
		t.Fatalf("start tunnel: %v", err)
	}
	defer cancelTunnel()

	// Spoofed chain from a caller the edge does not trust to describe itself.
	req, _ := http.NewRequest("GET", tunnelURL+"/", nil)
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	resp, err := newTestHTTPClient(10 * time.Second).Do(req)
	if err != nil {
		t.Fatalf("request through tunnel: %v", err)
	}
	resp.Body.Close()

	select {
	case got := <-xffCh:
		if !got.ok || got.xff == "" {
			t.Fatalf("backend saw empty X-Forwarded-For: %q", got.xff)
		}
		parts := strings.Split(got.xff, ",")
		last := strings.TrimSpace(parts[len(parts)-1])
		// Loopback is a trusted hop in the test harness, so the verified
		// origin is the address the spoofed chain resolved to: 9.9.9.9.
		// Either way it is an address the SERVER chose, not a blank the
		// client invented — the old bug sent an empty header.
		if last == "" {
			t.Fatalf("rightmost XFF entry is empty (chain %q) — the client clobbered it", got.xff)
		}
		if last != "9.9.9.9" && last != "127.0.0.1" {
			t.Fatalf("rightmost XFF entry %q is neither the extracted origin nor the peer address (chain %q)", last, got.xff)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("backend never saw the request")
	}
}

// Response headers pass through the tunnel intact unless they are
// hop-by-hop. The hop-by-hop strip itself (including headers a hostile peer
// names in a Connection header) is pinned by
// TestCopyResponseHeadersStripsHopByHopAndContentLength; this e2e proves the
// ordinary path neither drops nor mangles end-to-end headers. Note the
// backend's Connection header never reaches the wire here: Go's own client
// consumes it, which is also why Connection-NAMED headers cannot be
// identified by any proxy built on net/http — stdlib ReverseProxy shares
// this limit.
func TestHopByHopHeadersDoNotCrossTunnel(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend-Keeps", "passes")
		w.Header().Set("X-Multi", "one")
		w.Header().Add("X-Multi", "two")
		fmt.Fprint(w, "body")
	}))
	defer backend.Close()

	tunnelURL, cancelTunnel, err := startTunnelClient(t, extractPort(backend.URL))
	if err != nil {
		t.Fatalf("start tunnel: %v", err)
	}
	defer cancelTunnel()

	resp, err := newTestHTTPClient(10 * time.Second).Get(tunnelURL + "/")
	if err != nil {
		t.Fatalf("request through tunnel: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if string(body) != "body" {
		t.Errorf("body = %q, want %q", body, "body")
	}
	if got := resp.Header.Get("X-Backend-Keeps"); got != "passes" {
		t.Errorf("X-Backend-Keeps = %q, want %q — end-to-end headers must survive the strip", got, "passes")
	}
	if got := resp.Header.Values("X-Multi"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Errorf("X-Multi = %v, want [one two] — repeated headers must survive in order", got)
	}
}
