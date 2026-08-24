package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/maborak/mabo-tunnel/internal/protocol"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testWSConn returns a websocket.Conn from a real handshake. Tunnel
// registration needs a live conn to close on eviction; a hand-rolled one
// (e.g. wrapping net.Pipe in NewClient) blocks forever on the handshake read.
func testWSConn(t *testing.T) *websocket.Conn {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Hold the server side open; it unblocks when the test ends.
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(ts.Close)
	conn, _, err := (&websocket.Dialer{}).Dial("ws"+strings.TrimPrefix(ts.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial test websocket: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func testTunnelManager(t *testing.T) *TunnelManager {
	t.Helper()
	tm := NewTunnelManager("mabo-tunnel.test", 10000, 10100, testLogger())
	t.Cleanup(tm.Stop)
	return tm
}

// A subdomain reserved for a reconnecting user must not be claimable by a
// different user while the reservation window is open: public clients stay
// pointed at the URL through brief outages, so handing it to another tenant
// would redirect a victim's traffic into the attacker's tunnel.
func TestRegisterDeniesClaimOfAnotherUsersReservedSubdomain(t *testing.T) {
	tm := testTunnelManager(t)

	alice, err := tm.Register(RegisterOpts{Conn: testWSConn(t), Username: "alice", Plan: "pro", Subdomain: "app-ui", SessionID: "sess-alice"})
	if err != nil {
		t.Fatalf("alice register: %v", err)
	}
	tm.Unregister(alice.ID) // non-graceful → app-ui reserved for alice's session

	if _, err := tm.Register(RegisterOpts{Conn: testWSConn(t), Username: "mallory", Plan: "pro", Subdomain: "app-ui", SessionID: "sess-mallory"}); err == nil {
		t.Fatal("mallory claimed alice's reserved subdomain — a victim's public traffic would now route to the attacker")
	} else if !strings.Contains(err.Error(), "reserved") {
		t.Errorf("error should name the reservation, got: %v", err)
	}

	// The owner may reclaim it, even from a brand-new session (new process).
	again, err := tm.Register(RegisterOpts{Conn: testWSConn(t), Username: "alice", Plan: "pro", Subdomain: "app-ui", SessionID: "sess-alice-2"})
	if err != nil {
		t.Fatalf("owner reclaim of own reserved subdomain: %v", err)
	}
	if again.Subdomain != "app-ui" {
		t.Errorf("reclaim assigned %q, want app-ui", again.Subdomain)
	}
}

// Eviction of a live tunnel must require the same user AND session. Matching
// on SessionID alone would let a tenant presenting a victim's session ID tear
// down the victim's live tunnel and take the URL.
func TestRegisterEvictRequiresSameUserAndSession(t *testing.T) {
	tm := testTunnelManager(t)

	_, err := tm.Register(RegisterOpts{Conn: testWSConn(t), Username: "alice", Plan: "pro", Subdomain: "live-ui", SessionID: "sess-alice"})
	if err != nil {
		t.Fatalf("alice register: %v", err)
	}

	// Mallory presents alice's session ID verbatim.
	if _, err := tm.Register(RegisterOpts{Conn: testWSConn(t), Username: "mallory", Plan: "pro", Subdomain: "live-ui", SessionID: "sess-alice"}); err == nil {
		t.Fatal("a different user evicted a live tunnel by presenting the victim's session ID")
	}

	existing, ok := tm.LookupByHost("live-ui")
	if !ok || existing.Username != "alice" {
		t.Fatalf("alice's live tunnel did not survive the foreign eviction attempt (found=%v user=%q)", ok, existing.Username)
	}

	// The legitimate owner reconnecting with the same session does evict.
	again, err := tm.Register(RegisterOpts{Conn: testWSConn(t), Username: "alice", Plan: "pro", Subdomain: "live-ui", SessionID: "sess-alice"})
	if err != nil {
		t.Fatalf("same-user same-session reconnect: %v", err)
	}
	if again.Subdomain != "live-ui" {
		t.Errorf("reconnect assigned %q, want live-ui", again.Subdomain)
	}
	if stale := tm.LookupByID(existing.ID); stale != nil {
		t.Error("stale tunnel was not evicted on reconnect")
	}
}

// The session-reuse path (no explicit subdomain) must not hand a reserved
// subdomain to a session that belongs to someone else.
func TestReservedSubdomainReuseOnlyForSessionOwner(t *testing.T) {
	tm := testTunnelManager(t)

	alice, err := tm.Register(RegisterOpts{Conn: testWSConn(t), Username: "alice", Plan: "pro", SessionID: "sess-alice"})
	if err != nil {
		t.Fatalf("alice register: %v", err)
	}
	tm.Unregister(alice.ID) // reserves alice's random subdomain

	// Mallory guesses the session ID and connects with no subdomain request.
	mallory, err := tm.Register(RegisterOpts{Conn: testWSConn(t), Username: "mallory", Plan: "pro", SessionID: "sess-alice"})
	if err != nil {
		t.Fatalf("mallory register: %v", err)
	}
	if mallory.Subdomain == alice.Subdomain {
		t.Fatal("mallory's session-reuse lookup consumed alice's reservation")
	}

	// The real owner's reconnect still reuses it.
	alice2, err := tm.Register(RegisterOpts{Conn: testWSConn(t), Username: "alice", Plan: "pro", SessionID: "sess-alice"})
	if err != nil {
		t.Fatalf("alice reconnect: %v", err)
	}
	if alice2.Subdomain != alice.Subdomain {
		t.Errorf("alice reconnect got %q, want her reserved %q", alice2.Subdomain, alice.Subdomain)
	}
}

// The graceful flag is written by the read loop and read by Unregister from
// other goroutines; this exercises the pair concurrently for the race
// detector. A test that passes without -race proves nothing here.
func TestGracefulFlagAndUnregisterAreRaceFree(t *testing.T) {
	tm := testTunnelManager(t)
	tunnel, err := tm.Register(RegisterOpts{Conn: testWSConn(t), Username: "alice", Plan: "pro", SessionID: "sess-alice"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				tunnel.graceful.Store(true)
			}
		}
	}()

	tm.Unregister(tunnel.ID) // reads graceful while the writer flaps it

	close(stop)
	wg.Wait()
}

// The event channel bounds event COUNT; the byte bound must stop a peer that
// sends legitimate-sized chunks totaling more than the budget.
func TestProxiedConnByteBoundEnforced(t *testing.T) {
	pc := NewProxiedConn("c1", nil)
	if !pc.PushHeader(&protocol.RespHeaderFrame{ConnID: "c1", StatusCode: 200}) {
		t.Fatal("header push failed")
	}

	chunk := make([]byte, 64*1024)
	var pushed int
	overflowed := false
	for i := 0; i < maxProxiedBufferedBytes/len(chunk)+2; i++ {
		if !pc.PushBody(chunk) {
			overflowed = true
			break
		}
		pushed++
	}
	if !overflowed {
		t.Fatalf("pushed %d bytes without tripping the %d byte bound", pushed*len(chunk), maxProxiedBufferedBytes)
	}
	if !pc.Overflowed() {
		t.Error("Overflowed() = false after the byte bound was hit")
	}
}

// Consuming events must return byte budget: the bound is on buffered bytes,
// not on lifetime bytes.
func TestProxiedConnReleaseRestoresByteBudget(t *testing.T) {
	pc := NewProxiedConn("c1", nil)
	pc.PushHeader(&protocol.RespHeaderFrame{ConnID: "c1", StatusCode: 200})

	chunk := make([]byte, 32*1024)
	for i := 0; i < 10; i++ {
		if !pc.PushBody(chunk) {
			t.Fatal("push within budget failed")
		}
		ev, ok := <-pc.Events
		if !ok {
			t.Fatal("event channel closed prematurely")
		}
		pc.release(len(ev.Body))
	}
}

// A passthrough connection whose consumer falls behind by bytes must close,
// same as one that falls behind by count.
func TestStreamingConnByteBoundClosesConn(t *testing.T) {
	sc := &StreamingConn{
		ID:      "s1",
		DataCh:  make(chan []byte, streamingConnBuffer),
		CloseCh: make(chan struct{}),
	}

	chunk := make([]byte, 1024*1024)
	for i := 0; i < maxStreamBufferedBytes/len(chunk); i++ {
		if !sc.TrySend(chunk) {
			t.Fatalf("send %d within byte budget failed", i)
		}
	}
	if sc.TrySend(chunk) {
		t.Fatal("send past the byte budget succeeded")
	}
	select {
	case <-sc.CloseCh:
	default:
		t.Error("connection stayed open after the byte bound was exceeded")
	}
}

// Close reason tcp_eof must tear down a WebSocket passthrough stream, not
// just TCP-tunnel sockets — otherwise the public side of a dead local WS
// server lingers forever.
func TestCloseTCPEOFReachesWebSocketPassthrough(t *testing.T) {
	s := &Server{}
	tunnel := &Tunnel{}
	sc := &StreamingConn{ID: "c1", DataCh: make(chan []byte, 1), CloseCh: make(chan struct{})}
	tunnel.pending.Store("c1", sc)

	s.closeTCPConn(tunnel, "c1")

	select {
	case <-sc.CloseCh:
	default:
		t.Error("passthrough stream was not closed on tcp_eof")
	}
}
