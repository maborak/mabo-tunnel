package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maborak/mabo-tunnel/internal/client"
)

// The tunnel server is the in-process one from harness_test.go.

// slowBackendDelay is how long the /slow backend stalls. It only has to be
// long enough to be distinguishable from a normal round trip — the point is
// that a slow backend is not cut off, not how slow it is.
const slowBackendDelay = 1500 * time.Millisecond

// newLocalServer creates a local HTTP test server that handles all test scenarios.
func newLocalServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// GET / — simple HTML response
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><body><h1>Mabo Tunnel Test OK</h1></body></html>")
	})

	// GET /search?q=... — verify query params preserved
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"query": q})
	})

	// POST /api/data — echo back method and body
	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body failed", http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"method": r.Method,
			"body":   string(body),
		})
	})

	// GET /custom-headers — set custom response headers
	mux.HandleFunc("/custom-headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-One", "value-one")
		w.Header().Set("X-Custom-Two", "value-two")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "headers set")
	})

	// GET /not-found — returns 404
	mux.HandleFunc("/not-found", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "resource not found", http.StatusNotFound)
	})

	// GET /large — returns 500KB body
	mux.HandleFunc("/large", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		// Write 500KB of random-ish data (use deterministic pattern for verification).
		size := 500 * 1024
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i % 256)
		}
		w.Write(data)
	})

	// GET /concurrent — simple response for concurrent test
	mux.HandleFunc("/concurrent", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "concurrent-ok")
	})

	// GET /slow — delays before responding, to prove a slow backend is not
	// cut off. The delay only needs to exceed a normal round trip.
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(slowBackendDelay)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "slow-response-done")
	})

	return httptest.NewServer(mux)
}

// startTunnelClient starts the Mabo Tunnel client, waits for the tunnel URL, and returns it.
// Returns the tunnel URL, a cancel function to stop the client, and any error.
func startTunnelClient(t *testing.T, localPort int) (tunnelURL string, cancel context.CancelFunc, err error) {
	t.Helper()

	cfg := client.Config{
		ServerURL: "ws://" + tsHost,
		Token:     proToken,
		LocalPort: localPort,
	}

	c := client.New(cfg, client.NewDisplay(), nil, nil)

	readyCh := make(chan string, 1)
	c.OnReady = func(url string) {
		readyCh <- url
	}

	ctx, cancelFn := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Run(ctx)
	}()

	// Wait for the tunnel to be established or an error.
	select {
	case url := <-readyCh:
		return url, cancelFn, nil
	case e := <-errCh:
		cancelFn()
		return "", nil, fmt.Errorf("client exited before ready: %w", e)
	case <-time.After(15 * time.Second):
		cancelFn()
		return "", nil, fmt.Errorf("timeout waiting for tunnel to establish")
	}
}

// extractPort extracts the port from an httptest.Server URL like "http://127.0.0.1:12345".
func extractPort(url string) int {
	// URL format: http://127.0.0.1:PORT
	var port int
	fmt.Sscanf(url, "http://127.0.0.1:%d", &port)
	if port == 0 {
		fmt.Sscanf(url, "http://[::1]:%d", &port)
	}
	return port
}

func TestProxyPipeline(t *testing.T) {
	// 1. Start local test server.
	localServer := newLocalServer(t)
	defer localServer.Close()

	port := extractPort(localServer.URL)
	if port == 0 {
		t.Fatalf("could not extract port from local server URL: %s", localServer.URL)
	}
	t.Logf("Local test server running on port %d", port)

	// 2. Start Mabo Tunnel client connecting to the live tunnel service.
	tunnelURL, cancelClient, err := startTunnelClient(t, port)
	if err != nil {
		t.Fatalf("Failed to start tunnel client: %v", err)
	}
	t.Logf("Tunnel established: %s", tunnelURL)

	// Give the tunnel a moment to fully stabilize.
	time.Sleep(500 * time.Millisecond)

	httpClient := newTestHTTPClient(35 * time.Second)

	// --- Test: GET / (simple HTML) ---
	t.Run("GET_root_html", func(t *testing.T) {
		resp, err := httpClient.Get(tunnelURL + "/")
		if err != nil {
			t.Fatalf("GET / failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		expected := "<html><body><h1>Mabo Tunnel Test OK</h1></body></html>"
		if string(body) != expected {
			t.Errorf("GET / body mismatch.\n  got:  %q\n  want: %q", string(body), expected)
		} else {
			t.Logf("PASS: GET / returned expected HTML body (%d bytes)", len(body))
		}
	})

	// --- Test: GET with query params ---
	t.Run("GET_query_params", func(t *testing.T) {
		resp, err := httpClient.Get(tunnelURL + "/search?q=hello")
		if err != nil {
			t.Fatalf("GET /search?q=hello failed: %v", err)
		}
		defer resp.Body.Close()
		var result map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode JSON: %v", err)
		}
		if result["query"] != "hello" {
			t.Errorf("query param mismatch: got %q, want %q", result["query"], "hello")
		} else {
			t.Logf("PASS: GET /search?q=hello returned query=%q", result["query"])
		}
	})

	// --- Test: POST with JSON body ---
	t.Run("POST_json_body", func(t *testing.T) {
		payload := `{"key":"value","number":42}`
		resp, err := httpClient.Post(tunnelURL+"/api/data", "application/json", strings.NewReader(payload))
		if err != nil {
			t.Fatalf("POST /api/data failed: %v", err)
		}
		defer resp.Body.Close()
		var result map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode JSON: %v", err)
		}
		if result["method"] != "POST" {
			t.Errorf("method mismatch: got %q, want %q", result["method"], "POST")
		}
		if result["body"] != payload {
			t.Errorf("body mismatch: got %q, want %q", result["body"], payload)
		}
		if result["method"] == "POST" && result["body"] == payload {
			t.Logf("PASS: POST /api/data echoed method=%s and correct body", result["method"])
		}
	})

	// --- Test: Response headers ---
	t.Run("response_headers", func(t *testing.T) {
		resp, err := httpClient.Get(tunnelURL + "/custom-headers")
		if err != nil {
			t.Fatalf("GET /custom-headers failed: %v", err)
		}
		defer resp.Body.Close()
		io.ReadAll(resp.Body) // drain

		h1 := resp.Header.Get("X-Custom-One")
		h2 := resp.Header.Get("X-Custom-Two")
		if h1 != "value-one" {
			t.Errorf("X-Custom-One mismatch: got %q, want %q", h1, "value-one")
		}
		if h2 != "value-two" {
			t.Errorf("X-Custom-Two mismatch: got %q, want %q", h2, "value-two")
		}
		if h1 == "value-one" && h2 == "value-two" {
			t.Logf("PASS: Custom headers X-Custom-One=%q, X-Custom-Two=%q arrived correctly", h1, h2)
		}
	})

	// --- Test: 404 response ---
	t.Run("404_response", func(t *testing.T) {
		resp, err := httpClient.Get(tunnelURL + "/not-found")
		if err != nil {
			t.Fatalf("GET /not-found failed: %v", err)
		}
		defer resp.Body.Close()
		io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status code mismatch: got %d, want %d", resp.StatusCode, http.StatusNotFound)
		} else {
			t.Logf("PASS: GET /not-found returned status %d", resp.StatusCode)
		}
	})

	// --- Test: Large response (500KB) ---
	t.Run("large_response_500KB", func(t *testing.T) {
		resp, err := httpClient.Get(tunnelURL + "/large")
		if err != nil {
			t.Fatalf("GET /large failed: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read large response body: %v", err)
		}
		expectedSize := 500 * 1024
		if len(body) != expectedSize {
			t.Errorf("large response size mismatch: got %d bytes, want %d bytes", len(body), expectedSize)
		} else {
			// Verify pattern integrity.
			ok := true
			for i := 0; i < len(body); i++ {
				if body[i] != byte(i%256) {
					t.Errorf("large response data mismatch at byte %d: got %d, want %d", i, body[i], byte(i%256))
					ok = false
					break
				}
			}
			if ok {
				t.Logf("PASS: Large response received %d bytes with correct data pattern", len(body))
			}
		}
	})

	// --- Test: Multiple concurrent requests ---
	t.Run("concurrent_requests", func(t *testing.T) {
		const n = 10
		var wg sync.WaitGroup
		results := make([]error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				resp, err := httpClient.Get(tunnelURL + "/concurrent")
				if err != nil {
					results[idx] = fmt.Errorf("request %d failed: %w", idx, err)
					return
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				if string(body) != "concurrent-ok" {
					results[idx] = fmt.Errorf("request %d body mismatch: got %q", idx, string(body))
				}
			}(i)
		}
		wg.Wait()
		failures := 0
		for i, err := range results {
			if err != nil {
				t.Errorf("Concurrent request %d: %v", i, err)
				failures++
			}
		}
		if failures == 0 {
			t.Logf("PASS: All %d concurrent requests succeeded", n)
		} else {
			t.Errorf("%d of %d concurrent requests failed", failures, n)
		}
	})

	// --- Test: Slow response (5s delay) ---
	t.Run("slow_response", func(t *testing.T) {
		start := time.Now()
		resp, err := httpClient.Get(tunnelURL + "/slow")
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("GET /slow failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "slow-response-done" {
			t.Errorf("slow response body mismatch: got %q", string(body))
		} else {
			t.Logf("PASS: Slow response received in %v with correct body", elapsed.Round(time.Millisecond))
		}
		if elapsed < slowBackendDelay {
			t.Errorf("slow response was too fast (%v), expected >= %v", elapsed, slowBackendDelay)
		}
		if elapsed > 30*time.Second {
			t.Errorf("slow response took too long (%v), expected < 30s", elapsed)
		}
	})

	// --- Test: Client disconnect ---
	t.Run("client_disconnect", func(t *testing.T) {
		// Stop the client.
		cancelClient()
		// Wait for the server to notice the WebSocket closed, rather than
		// guessing how long that takes.
		waitFor(t, 10*time.Second, func() bool {
			probe := newTestHTTPClient(2 * time.Second)
			resp, err := probe.Get(tunnelURL + "/")
			if err != nil {
				return true
			}
			resp.Body.Close()
			return resp.StatusCode == http.StatusNotFound
		})

		disconnectClient := newTestHTTPClient(10 * time.Second)
		resp, err := disconnectClient.Get(tunnelURL + "/")
		if err != nil {
			// Connection error is acceptable — tunnel is closed.
			t.Logf("PASS: After client disconnect, request got error (expected): %v", err)
			return
		}
		defer resp.Body.Close()
		io.ReadAll(resp.Body)
		// Server should return an error status (404 tunnel not found, or 502 bad gateway).
		if resp.StatusCode >= 400 {
			t.Logf("PASS: After client disconnect, request returned status %d (tunnel gone)", resp.StatusCode)
		} else {
			t.Errorf("Expected error status after client disconnect, got %d", resp.StatusCode)
		}
	})
}

// TestRandomPayloadIntegrity sends a random binary payload via POST and verifies it arrives intact.
func TestRandomPayloadIntegrity(t *testing.T) {
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write(body) // echo back
	}))
	defer localServer.Close()

	port := extractPort(localServer.URL)
	if port == 0 {
		t.Fatalf("could not extract port from local server URL: %s", localServer.URL)
	}

	tunnelURL, cancelClient, err := startTunnelClient(t, port)
	if err != nil {
		t.Fatalf("Failed to start tunnel client: %v", err)
	}
	defer cancelClient()
	time.Sleep(500 * time.Millisecond)

	// Generate a random payload (64KB).
	payload := make([]byte, 64*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("Failed to generate random payload: %v", err)
	}

	httpClient := newTestHTTPClient(30 * time.Second)
	resp, err := httpClient.Post(tunnelURL+"/echo", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /echo failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read echo response: %v", err)
	}

	if !bytes.Equal(body, payload) {
		t.Errorf("Random payload integrity check failed: sent %d bytes, got %d bytes back", len(payload), len(body))
		if len(body) > 0 && len(payload) > 0 {
			// Find first mismatch.
			minLen := len(body)
			if len(payload) < minLen {
				minLen = len(payload)
			}
			for i := 0; i < minLen; i++ {
				if body[i] != payload[i] {
					t.Errorf("First mismatch at byte %d: got %02x, want %02x", i, body[i], payload[i])
					break
				}
			}
		}
	} else {
		t.Logf("PASS: Random 64KB payload echoed back correctly")
	}
}
