package client

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestBodyPipeStreamsInOrder(t *testing.T) {
	bp := newBodyPipe(1024)

	go func() {
		for i := 0; i < 10; i++ {
			bp.Send([]byte{byte('0' + i)})
		}
		bp.Close()
	}()

	got, err := io.ReadAll(bp)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "0123456789" {
		t.Errorf("body = %q, want %q", got, "0123456789")
	}
}

func TestBodyPipeReturnsEOFWhenClosedEmpty(t *testing.T) {
	bp := newBodyPipe(0)
	bp.Close()

	got, err := io.ReadAll(bp)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("body = %q, want empty", got)
	}
}

// A truncated upload delivered as a complete one is the same class of bug as a
// truncated response: the request must fail instead.
func TestBodyPipeFailsRequestOnOverflow(t *testing.T) {
	bp := newBodyPipe(0)

	overflowed := false
	for i := 0; i < bodyQueue+10; i++ {
		if !bp.Send([]byte("x")) {
			overflowed = true
			break
		}
	}
	if !overflowed {
		t.Fatal("expected the queue to overflow")
	}

	_, err := io.ReadAll(bp)
	if !errors.Is(err, ErrBodyOverflow) {
		t.Errorf("read error = %v, want ErrBodyOverflow", err)
	}
}

func TestBodyPipeCloseWithErrorSurfacesToReader(t *testing.T) {
	bp := newBodyPipe(0)
	sentinel := errors.New("caller went away")
	bp.CloseWithError(sentinel)

	if _, err := io.ReadAll(bp); !errors.Is(err, sentinel) {
		t.Errorf("read error = %v, want %v", err, sentinel)
	}
}

func TestBodyPipeCapturesLeadingBytesOnly(t *testing.T) {
	bp := newBodyPipe(4)
	bp.Send([]byte("abc"))
	bp.Send([]byte("defgh"))
	bp.Close()

	if got := string(bp.Captured()); got != "abcd" {
		t.Errorf("Captured() = %q, want %q", got, "abcd")
	}
}

func TestBodyPipeSendAfterCloseIsSafe(t *testing.T) {
	bp := newBodyPipe(0)
	bp.Close()
	if bp.Send([]byte("late")) {
		t.Error("Send after Close should report failure, not panic or queue")
	}
}

func testConnPair(t *testing.T) (server, client net.Conn) {
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

// Bytes queued before the socket is dialed must still be delivered, in order.
// This is what stops a second frame for a connection still being dialed from
// opening a second socket or racing ahead of the first.
func TestLocalConnQueuesBeforeAttach(t *testing.T) {
	srv, cli := testConnPair(t)
	defer srv.Close()
	defer cli.Close()

	lc := newLocalConn()
	defer lc.Close()

	for i := 0; i < 5; i++ {
		if !lc.Send([]byte{byte(i)}) {
			t.Fatalf("send %d before attach failed", i)
		}
	}

	lc.Attach(srv)

	got := make([]byte, 5)
	cli.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(cli, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, []byte{0, 1, 2, 3, 4}) {
		t.Errorf("got %v, want [0 1 2 3 4] — queued writes were lost or reordered", got)
	}
}

func TestLocalConnSendAfterCloseFails(t *testing.T) {
	lc := newLocalConn()
	lc.Close()
	if lc.Send([]byte("x")) {
		t.Error("Send after Close should report failure")
	}
}

func TestReconnectBackoffGrowsAndCaps(t *testing.T) {
	p := ReconnectPolicy{
		InitialDelay: time.Second,
		MaxDelay:     10 * time.Second,
		Multiplier:   2.0,
	}

	if got := p.NextDelay(0); got != time.Second {
		t.Errorf("NextDelay(0) = %v, want 1s", got)
	}
	if got := p.NextDelay(2); got != 4*time.Second {
		t.Errorf("NextDelay(2) = %v, want 4s", got)
	}
	if got := p.NextDelay(20); got != 10*time.Second {
		t.Errorf("NextDelay(20) = %v, want the 10s cap", got)
	}
}

// Without jitter every client that was attached to a restarting server comes
// back on exactly the same schedule.
func TestReconnectBackoffJitterSpreadsRetries(t *testing.T) {
	p := DefaultReconnectPolicy()

	seen := make(map[time.Duration]bool)
	for i := 0; i < 50; i++ {
		seen[p.NextDelay(3)] = true
	}
	if len(seen) < 2 {
		t.Error("NextDelay returned the same value every time — jitter is not applied")
	}

	for d := range seen {
		if d > p.MaxDelay {
			t.Errorf("jittered delay %v exceeded MaxDelay %v", d, p.MaxDelay)
		}
	}
}
