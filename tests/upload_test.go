package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/maborak/mabo-tunnel/internal/client"
)

// startTunnelTo runs a tunnel client forwarding to the given local port and
// returns the public URL once it is up.
func startTunnelTo(t *testing.T, localPort int, subdomain string) string {
	t.Helper()

	cl := client.New(client.Config{
		ServerURL: "ws://" + tsHost,
		Token:     proToken,
		LocalPort: localPort,
		Subdomain: subdomain,
	}, client.NewDisplay(), nil, nil)

	readyCh := make(chan string, 1)
	cl.OnReady = func(url string) { readyCh <- url }

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go cl.Run(ctx)

	select {
	case url := <-readyCh:
		return url
	case <-time.After(10 * time.Second):
		t.Fatal("tunnel client did not become ready")
		return ""
	}
}

// A large upload must arrive intact. The request head and body travel as
// separate frames now, so this covers the reassembly on the client side.
func TestLargeUploadStreamsIntact(t *testing.T) {
	const bodySize = 4 << 20 // 4 MiB

	var gotSum string
	var gotLen int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		n, err := io.Copy(h, r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusInternalServerError)
			return
		}
		gotLen = int(n)
		gotSum = hex.EncodeToString(h.Sum(nil))
		fmt.Fprintf(w, "%s %d", gotSum, n)
	}))
	defer backend.Close()

	tunnelURL := startTunnelTo(t, extractPort(backend.URL), "upload")

	payload := make([]byte, bodySize)
	rng := rand.New(rand.NewSource(1))
	rng.Read(payload)
	wantSum := sha256.Sum256(payload)

	httpClient := newTestHTTPClient(60 * time.Second)
	resp, err := httpClient.Post(tunnelURL+"/upload", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}

	body, _ := io.ReadAll(resp.Body)
	want := fmt.Sprintf("%s %d", hex.EncodeToString(wantSum[:]), bodySize)
	if string(body) != want {
		t.Errorf("backend saw %q, want %q (got %d bytes, checksum %s)", body, want, gotLen, gotSum)
	}
}

// The body has to start reaching the local server before the upload finishes,
// or a large POST stalls for its entire duration at the edge first.
func TestUploadReachesBackendBeforeItFinishes(t *testing.T) {
	firstByte := make(chan time.Time, 1)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1)
		if _, err := io.ReadFull(r.Body, buf); err == nil {
			select {
			case firstByte <- time.Now():
			default:
			}
		}
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	tunnelURL := startTunnelTo(t, extractPort(backend.URL), "slowupload")

	// A body that trickles: one chunk now, the rest after a delay.
	const tail = 500 * time.Millisecond
	pr, pw := io.Pipe()
	go func() {
		pw.Write(bytes.Repeat([]byte("a"), 1024))
		time.Sleep(tail)
		pw.Write(bytes.Repeat([]byte("b"), 1024))
		pw.Close()
	}()

	start := time.Now()
	req, err := http.NewRequest("POST", tunnelURL+"/trickle", pr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	httpClient := newTestHTTPClient(30 * time.Second)
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	select {
	case at := <-firstByte:
		elapsed := at.Sub(start)
		if elapsed >= tail {
			t.Errorf("backend saw the first byte after %v, expected well under %v — the upload is being buffered whole before forwarding",
				elapsed.Round(time.Millisecond), tail)
		} else {
			t.Logf("backend saw the first byte after %v (upload finished at ~%v)", elapsed.Round(time.Millisecond), tail)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backend never received the body")
	}
}

// Binary framing carries arbitrary bytes. This is the case JSON handled by
// base64-encoding every payload.
func TestBinaryPayloadRoundTripsThroughTunnel(t *testing.T) {
	payload := make([]byte, 256*1024)
	rng := rand.New(rand.NewSource(7))
	rng.Read(payload)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(payload)
	}))
	defer backend.Close()

	tunnelURL := startTunnelTo(t, extractPort(backend.URL), "binary")

	httpClient := newTestHTTPClient(30 * time.Second)
	resp, err := httpClient.Get(tunnelURL + "/blob")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// An upload past the tunnel's limit must be refused, not silently truncated.
func TestOversizeUploadRejected(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	tunnelURL := startTunnelTo(t, extractPort(backend.URL), "toobig")

	payload := bytes.Repeat([]byte("x"), 11<<20) // over the 10 MiB limit
	httpClient := newTestHTTPClient(60 * time.Second)
	resp, err := httpClient.Post(tunnelURL+"/big", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		// A connection error is also an acceptable rejection.
		t.Logf("POST rejected at the connection level: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}
}
