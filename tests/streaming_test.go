package tests

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/maborak/mabo-tunnel/internal/client"
)

// TestStreamingSSEThroughTunnel verifies that Server-Sent Events flow through
// the tunnel incrementally rather than being buffered until the backend closes
// its response. It spins up an in-process Mabo Tunnel server, an SSE backend, and
// a tunnel client, then measures the gap between each event arriving at the
// public caller.
func TestStreamingSSEThroughTunnel(t *testing.T) {
	// 1. Local SSE backend: emits 5 events spaced 300ms apart.
	const numEvents = 5
	const eventGap = 300 * time.Millisecond
	sseBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		for i := 0; i < numEvents; i++ {
			fmt.Fprintf(w, "event: tick\ndata: %d\n\n", i)
			if f != nil {
				f.Flush()
			}
			time.Sleep(eventGap)
		}
	}))
	defer sseBackend.Close()

	backendPort := extractPort(sseBackend.URL)
	if backendPort == 0 {
		t.Fatalf("could not extract backend port from %s", sseBackend.URL)
	}

	// 2. Tunnel client against the shared in-process server from the harness,
	//    forwarding to the SSE backend.
	cfg := client.Config{
		ServerURL: "ws://" + tsHost,
		Token:     proToken,
		LocalPort: backendPort,
		Subdomain: "sse",
	}
	display := client.NewDisplay()
	cl := client.New(cfg, display, nil, nil)

	readyCh := make(chan string, 1)
	cl.OnReady = func(url string) { readyCh <- url }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go cl.Run(ctx)

	select {
	case <-readyCh:
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel client did not become ready in 5s")
	}

	// 3. Public-side request. The harness client dials the test server
	//    regardless of the hostname, so <subdomain>.<domain> needs no DNS.
	//    No overall timeout — we're testing streaming.
	httpClient := newTestHTTPClient(0)

	publicURL := "http://" + tunnelHost("sse") + "/stream"
	req, err := http.NewRequest("GET", publicURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("public GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}

	// 5. Read events with a bufio.Scanner and record the wall-clock arrival
	//    of each "data:" line. If the tunnel buffers the whole response,
	//    all events arrive essentially at the same moment (close to
	//    numEvents*eventGap).
	scanner := bufio.NewScanner(resp.Body)
	start := time.Now()
	var arrivals []time.Duration
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			arrivals = append(arrivals, time.Since(start))
			if len(arrivals) == numEvents {
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner: %v", err)
	}
	if len(arrivals) != numEvents {
		t.Fatalf("got %d events, want %d", len(arrivals), numEvents)
	}

	t.Logf("SSE event arrival offsets: %v", arrivals)

	// 6. Assertion: the first event should arrive well before the last —
	//    specifically, the first event must arrive no later than half the
	//    total backend generation time. If buffering is in effect, first
	//    and last arrive together near (numEvents-1)*eventGap.
	totalGenTime := time.Duration(numEvents-1) * eventGap
	firstEventDeadline := totalGenTime / 2
	if arrivals[0] > firstEventDeadline {
		t.Errorf(
			"first event arrived at %v, expected < %v — tunnel is buffering SSE instead of streaming",
			arrivals[0], firstEventDeadline,
		)
	}

	// Also require that events are genuinely spread out: the gap between
	// first and last arrival should be at least half the backend's gen time.
	spread := arrivals[numEvents-1] - arrivals[0]
	minSpread := totalGenTime / 2
	if spread < minSpread {
		t.Errorf(
			"event arrival spread = %v, expected >= %v — events are clumping, suggests buffering",
			spread, minSpread,
		)
	}
}
