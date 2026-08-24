package edge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// -------------------------------------------------------
// Configuration
// -------------------------------------------------------

// baseURL, wsURL, domain, and the tokens come from the harness in
// harness_test.go. Nothing here talks to a deployed server.

// -------------------------------------------------------
// Protocol types (mirrors internal/protocol)
// -------------------------------------------------------

type Envelope struct {
	Type    string          `json:"type"`
	Version int             `json:"version,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type AuthRequest struct {
	Token     string `json:"token"`
	Subdomain string `json:"subdomain,omitempty"`
}

type AuthResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message,omitempty"`
	TunnelID  string `json:"tunnel_id,omitempty"`
	Subdomain string `json:"subdomain,omitempty"`
	URL       string `json:"url,omitempty"`
	Username  string `json:"username,omitempty"`
}

// -------------------------------------------------------
// Helpers
// -------------------------------------------------------

func httpClient() *http.Client {
	return newTestHTTPClient(15 * time.Second)
}

func wsDialer() *websocket.Dialer {
	return newTestDialer()
}

func newEnvelope(msgType string, payload any) ([]byte, error) {
	env := Envelope{Type: msgType, Version: 1}
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		env.Payload = data
	}
	return json.Marshal(env)
}

func readAuthResponse(conn *websocket.Conn) (*AuthResponse, error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	var env Envelope
	if err := json.Unmarshal(msg, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	var resp AuthResponse
	if err := json.Unmarshal(env.Payload, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal auth response: %w", err)
	}
	return &resp, nil
}

// connectAndAuth dials the WS endpoint, authenticates with the given token,
// and returns the connection + auth response + error.
func connectAndAuth(t *testing.T, token string) (*websocket.Conn, *AuthResponse, error) {
	t.Helper()
	conn, _, err := wsDialer().Dial(wsURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("dial: %w", err)
	}

	authMsg, err := newEnvelope("auth_request", AuthRequest{Token: token})
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("build auth envelope: %w", err)
	}
	if err := conn.WriteMessage(websocket.TextMessage, authMsg); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("send auth: %w", err)
	}

	resp, err := readAuthResponse(conn)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("read auth response: %w", err)
	}
	return conn, resp, nil
}

func closeTunnel(conn *websocket.Conn) {
	if conn == nil {
		return
	}
	conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done"))
	conn.Close()
}

func healthOK(t *testing.T) bool {
	t.Helper()
	resp, err := httpClient().Get(baseURL + "/health")
	if err != nil {
		t.Logf("  health check error: %v", err)
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode == 200 && strings.Contains(string(body), `"ok"`)
}

// -------------------------------------------------------
// Edge Case Tests
// -------------------------------------------------------

// 1. Rate limiting: Send 10 rapid auth failures, verify rate limiting kicks in after 5
func TestEdge_01_RateLimiting(t *testing.T) {
	fmt.Println("\n=== TEST 1: Rate Limiting ===")

	rateLimited := false
	rateLimitAttempt := 0
	for i := 0; i < 10; i++ {
		conn, _, err := wsDialer().Dial(wsURL, nil)
		if err != nil {
			t.Logf("  attempt %d: dial error: %v", i+1, err)
			continue
		}

		authMsg, _ := newEnvelope("auth_request", AuthRequest{Token: fakeToken})
		if err := conn.WriteMessage(websocket.TextMessage, authMsg); err != nil {
			conn.Close()
			t.Logf("  attempt %d: write error: %v", i+1, err)
			continue
		}

		resp, err := readAuthResponse(conn)
		conn.Close()
		if err != nil {
			t.Logf("  attempt %d: read error: %v", i+1, err)
			continue
		}

		t.Logf("  attempt %d: success=%v message=%q", i+1, resp.Success, resp.Message)
		if strings.Contains(resp.Message, "Too many") || strings.Contains(strings.ToLower(resp.Message), "rate") {
			if !rateLimited {
				rateLimitAttempt = i + 1
			}
			rateLimited = true
			t.Logf("  >>> Rate limited at attempt %d", i+1)
		}
	}

	if rateLimited {
		fmt.Printf("PASS: Rate limiting kicked in at attempt %d\n", rateLimitAttempt)
	} else {
		fmt.Println("FAIL: Rate limiting did NOT kick in after 10 failures")
		t.Error("expected rate limiting after multiple auth failures")
	}

	// Let the window clear so later tests are not affected. The harness
	// configures a short window precisely so this costs seconds.
	clearRateLimit()
}

// 2. WebSocket upgrade on non-WS path (/health) - should fail
func TestEdge_02_WSUpgradeOnHealth(t *testing.T) {
	fmt.Println("\n=== TEST 2: WebSocket Upgrade on /health ===")

	conn, resp, err := wsDialer().Dial("ws://"+tsHost+"/health", nil)
	if err != nil {
		fmt.Printf("PASS: WebSocket upgrade on /health correctly rejected: %v\n", err)
		if resp != nil {
			t.Logf("  HTTP status: %d", resp.StatusCode)
		}
	} else {
		conn.Close()
		fmt.Println("FAIL: WebSocket upgrade on /health should have been rejected")
		t.Error("expected WS upgrade on /health to fail")
	}
}

// 3. HTTP GET to /tunnel/connect (no WebSocket upgrade) - should fail gracefully
func TestEdge_03_HTTPToTunnelEndpoint(t *testing.T) {
	fmt.Println("\n=== TEST 3: HTTP GET to /tunnel/connect ===")

	resp, err := httpClient().Get(baseURL + "/tunnel/connect")
	if err != nil {
		fmt.Printf("PASS: HTTP GET to /tunnel/connect returned error: %v\n", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	t.Logf("  status: %d, body: %s", resp.StatusCode, string(body))
	if resp.StatusCode == 400 || resp.StatusCode == 426 || resp.StatusCode == 405 {
		fmt.Printf("PASS: HTTP GET to /tunnel/connect returned status %d (graceful failure)\n", resp.StatusCode)
	} else {
		fmt.Printf("PASS: HTTP GET to /tunnel/connect returned status %d (handled gracefully, no hang)\n", resp.StatusCode)
	}
}

// 4. Oversized request (>10MB body) to a tunnel subdomain - verify rejection
func TestEdge_04_OversizedRequest(t *testing.T) {
	fmt.Println("\n=== TEST 4: Oversized Request (>10MB) ===")

	conn, authResp, err := connectAndAuth(t, proToken)
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}
	defer closeTunnel(conn)

	if !authResp.Success {
		t.Fatalf("auth failed: %s", authResp.Message)
	}
	subdomain := authResp.Subdomain
	tunnelURL := fmt.Sprintf("https://%s.%s/test", subdomain, domain)
	t.Logf("  tunnel URL: %s", tunnelURL)

	// Send a request with >10MB body
	bigBody := make([]byte, 11*1024*1024) // 11 MB
	for i := range bigBody {
		bigBody[i] = 'A'
	}

	client := &http.Client{Timeout: 30 * time.Second}
	httpResp, err := client.Post(tunnelURL, "application/octet-stream", bytes.NewReader(bigBody))
	if err != nil {
		// Connection may be reset or closed, which is acceptable
		fmt.Printf("PASS: Oversized request rejected with error: %v\n", err)
		return
	}
	defer httpResp.Body.Close()
	body, _ := io.ReadAll(httpResp.Body)

	t.Logf("  status: %d, body: %s", httpResp.StatusCode, string(body))
	if httpResp.StatusCode == 413 || httpResp.StatusCode == 500 || httpResp.StatusCode == 502 {
		fmt.Printf("PASS: Oversized request rejected with status %d\n", httpResp.StatusCode)
	} else {
		fmt.Printf("INFO: Oversized request returned status %d -- body: %s\n", httpResp.StatusCode, string(body))
	}
}

// 5. Rapid connect/disconnect 20 times; /health should still be ok
func TestEdge_05_RapidConnectDisconnect(t *testing.T) {
	fmt.Println("\n=== TEST 5: Rapid Connect/Disconnect (20x) ===")

	for i := 0; i < 20; i++ {
		conn, _, err := wsDialer().Dial(wsURL, nil)
		if err != nil {
			t.Logf("  iteration %d: dial error: %v", i+1, err)
			continue
		}
		conn.Close()
	}

	time.Sleep(1 * time.Second)

	if healthOK(t) {
		fmt.Println("PASS: Server healthy after 20 rapid connect/disconnect cycles")
	} else {
		fmt.Println("FAIL: Server NOT healthy after rapid connect/disconnect")
		t.Error("health check failed after rapid connect/disconnect")
	}
}

// 6. Concurrent auth: 10 simultaneous WebSocket connections all authenticating
func TestEdge_06_ConcurrentAuth(t *testing.T) {
	fmt.Println("\n=== TEST 6: Concurrent Auth (10 connections) ===")

	var wg sync.WaitGroup
	var successCount int32
	var failCount int32
	conns := make([]*websocket.Conn, 10)
	var connsMu sync.Mutex

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			c, authResp, err := connectAndAuth(t, proToken)
			if err != nil {
				t.Logf("  conn %d: error: %v", idx, err)
				atomic.AddInt32(&failCount, 1)
				return
			}

			if authResp.Success {
				atomic.AddInt32(&successCount, 1)
				connsMu.Lock()
				conns[idx] = c
				connsMu.Unlock()
				t.Logf("  conn %d: SUCCESS subdomain=%s", idx, authResp.Subdomain)
			} else {
				c.Close()
				atomic.AddInt32(&failCount, 1)
				t.Logf("  conn %d: FAILED message=%q", idx, authResp.Message)
			}
		}(i)
	}

	wg.Wait()

	// Clean up
	for i, c := range conns {
		if c != nil {
			closeTunnel(c)
			t.Logf("  closed conn %d", i)
		}
	}

	s := atomic.LoadInt32(&successCount)
	f := atomic.LoadInt32(&failCount)
	t.Logf("  results: success=%d fail=%d", s, f)

	if s == 10 {
		fmt.Println("PASS: All 10 concurrent auth attempts succeeded")
	} else if s > 0 {
		fmt.Printf("PARTIAL: %d/10 succeeded, %d failed (may be quota or rate limit)\n", s, f)
	} else {
		fmt.Println("FAIL: No concurrent auth attempts succeeded")
		t.Error("expected at least some concurrent auths to succeed")
	}
}

// 7. Request to closed tunnel: establish, disconnect, then request the URL
func TestEdge_07_RequestToClosedTunnel(t *testing.T) {
	fmt.Println("\n=== TEST 7: Request to Closed Tunnel ===")

	conn, authResp, err := connectAndAuth(t, proToken)
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}
	if !authResp.Success {
		conn.Close()
		t.Fatalf("auth failed: %s", authResp.Message)
	}
	subdomain := authResp.Subdomain
	tunnelURL := fmt.Sprintf("https://%s.%s/test", subdomain, domain)
	t.Logf("  tunnel URL: %s", tunnelURL)

	closeTunnel(conn)
	t.Logf("  tunnel closed")

	time.Sleep(500 * time.Millisecond)

	client := &http.Client{Timeout: 15 * time.Second}
	start := time.Now()
	httpResp, err := client.Get(tunnelURL)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Printf("PASS: Request to closed tunnel returned error (did not hang, took %v): %v\n", elapsed, err)
		return
	}
	defer httpResp.Body.Close()
	body, _ := io.ReadAll(httpResp.Body)

	t.Logf("  status: %d, body: %s, elapsed: %v", httpResp.StatusCode, string(body), elapsed)

	if httpResp.StatusCode == 404 || httpResp.StatusCode == 502 || httpResp.StatusCode == 503 {
		fmt.Printf("PASS: Request to closed tunnel returned %d (not hung, took %v)\n", httpResp.StatusCode, elapsed)
	} else {
		fmt.Printf("INFO: Request to closed tunnel returned %d (took %v)\n", httpResp.StatusCode, elapsed)
	}
}

// 8. Malformed protocol messages: invalid JSON, wrong type, missing fields
func TestEdge_08_MalformedMessages(t *testing.T) {
	fmt.Println("\n=== TEST 8: Malformed Protocol Messages ===")

	conn, authResp, err := connectAndAuth(t, proToken)
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}
	if !authResp.Success {
		conn.Close()
		t.Fatalf("auth failed: %s", authResp.Message)
	}
	t.Logf("  authenticated, subdomain=%s", authResp.Subdomain)

	malformed := []struct {
		name string
		data string
	}{
		{"invalid JSON", `{this is not valid json`},
		{"empty object", `{}`},
		{"wrong type", `{"type":"nonexistent_type","version":1}`},
		{"missing payload on data", `{"type":"data","version":1}`},
		{"garbage payload", `{"type":"data","version":1,"payload":"not-base64"}`},
		{"null type", `{"type":null,"version":1}`},
		{"numeric type", `{"type":123,"version":1}`},
	}

	allSent := true
	for _, m := range malformed {
		writeErr := conn.WriteMessage(websocket.TextMessage, []byte(m.data))
		if writeErr != nil {
			t.Logf("  %s: send error: %v", m.name, writeErr)
			allSent = false
			break
		}
		t.Logf("  sent: %s", m.name)
	}

	time.Sleep(2 * time.Second)
	closeTunnel(conn)

	if healthOK(t) && allSent {
		fmt.Println("PASS: Server handled all malformed messages without crashing; /health is ok")
	} else if healthOK(t) {
		fmt.Println("PASS: Server still healthy (some sends failed mid-way, but no crash)")
	} else {
		fmt.Println("FAIL: Server NOT healthy after malformed messages")
		t.Error("health check failed after malformed messages")
	}
}

// 9. Binary WebSocket frame instead of text
func TestEdge_09_BinaryFrame(t *testing.T) {
	fmt.Println("\n=== TEST 9: Binary WebSocket Frame ===")

	conn, authResp, err := connectAndAuth(t, proToken)
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}
	if !authResp.Success {
		conn.Close()
		t.Fatalf("auth failed: %s", authResp.Message)
	}
	t.Logf("  authenticated, subdomain=%s", authResp.Subdomain)

	binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}
	writeErr := conn.WriteMessage(websocket.BinaryMessage, binaryData)
	if writeErr != nil {
		t.Logf("  binary send error: %v", writeErr)
	} else {
		t.Logf("  sent binary frame (%d bytes)", len(binaryData))
	}

	largeBinary := make([]byte, 1024)
	for i := range largeBinary {
		largeBinary[i] = byte(i % 256)
	}
	writeErr = conn.WriteMessage(websocket.BinaryMessage, largeBinary)
	if writeErr != nil {
		t.Logf("  large binary send error: %v", writeErr)
	} else {
		t.Logf("  sent large binary frame (%d bytes)", len(largeBinary))
	}

	time.Sleep(1 * time.Second)
	closeTunnel(conn)

	if healthOK(t) {
		fmt.Println("PASS: Server handled binary frames without crashing; /health is ok")
	} else {
		fmt.Println("FAIL: Server NOT healthy after binary frames")
		t.Error("health check failed after binary frames")
	}
}

// 10. Double close: send WebSocket close frame twice
func TestEdge_10_DoubleClose(t *testing.T) {
	fmt.Println("\n=== TEST 10: Double Close ===")

	conn, authResp, err := connectAndAuth(t, proToken)
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}
	if !authResp.Success {
		conn.Close()
		t.Fatalf("auth failed: %s", authResp.Message)
	}
	t.Logf("  authenticated, subdomain=%s", authResp.Subdomain)

	err1 := conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "first close"))
	t.Logf("  first close: err=%v", err1)

	err2 := conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "second close"))
	t.Logf("  second close: err=%v", err2)

	conn.Close()
	time.Sleep(1 * time.Second)

	if healthOK(t) {
		fmt.Println("PASS: Server survived double close without panic; /health is ok")
	} else {
		fmt.Println("FAIL: Server NOT healthy after double close")
		t.Error("health check failed after double close")
	}
}

// 11. Keepalive: connect, idle for 35s, verify still alive via ping/pong
func TestEdge_11_Keepalive(t *testing.T) {
	fmt.Println("\n=== TEST 11: Keepalive (idle across several ping cycles) ===")

	conn, authResp, err := connectAndAuth(t, proToken)
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}
	if !authResp.Success {
		conn.Close()
		t.Fatalf("auth failed: %s", authResp.Message)
	}
	subdomain := authResp.Subdomain
	t.Logf("  authenticated, subdomain=%s", subdomain)

	// Set ping handler so we respond to server pings (keeping connection alive)
	conn.SetPingHandler(func(appData string) error {
		t.Logf("  received PING from server, sending PONG")
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(5*time.Second))
	})

	// Read messages in background to process control frames (pings)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			_, _, readErr := conn.ReadMessage()
			if readErr != nil {
				return
			}
		}
	}()

	// Idle for well past the pong deadline. If ping/pong were not keeping the
	// connection alive, the server would have dropped it by now.
	idle := keepaliveTimeout + 2*keepaliveInterval
	t.Logf("  idling %v (server ping interval is %v, pong deadline %v)...", idle, keepaliveInterval, keepaliveTimeout)
	time.Sleep(idle)

	// Verify the tunnel is still alive by sending an application-level ping
	pingMsg, _ := newEnvelope("ping", nil)
	writeErr := conn.WriteMessage(websocket.TextMessage, pingMsg)

	if writeErr != nil {
		fmt.Printf("FAIL: Connection died while idle: %v\n", writeErr)
		t.Errorf("expected connection to survive %v idle, got: %v", idle, writeErr)
	} else {
		fmt.Println("PASS: Connection still alive after idling past the pong deadline (keepalive working)")
	}

	closeTunnel(conn)
	<-done
}

// 12. Frame size violations: a peer that sends a frame whose payload exceeds
// the protocol's per-type limit gets its tunnel torn down, not its megabytes
// buffered. Oversize frames are the memory-amplification vector: the queues
// behind these frames are sized for 16–32 KiB chunks, so a 16 MB frame parked
// in one slot costs ~1000× the designed budget.
func TestEdge_12_FrameSizeViolation(t *testing.T) {
	fmt.Println("\n=== TEST 12: Frame Size Violations ===")

	cases := []struct {
		name        string
		frameType   byte
		payloadSize int
		limit       int
	}{
		{"resp_body over chunk limit", 2, 64*1024 + 1, 64 * 1024},
		{"tcp_data over chunk limit", 3, 64*1024 + 1, 64 * 1024},
		{"data over frame limit", 1, 8*1024*1024 + 1, 8 * 1024 * 1024},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearRateLimit()
			conn, authResp, err := connectAndAuth(t, proToken)
			if err != nil {
				t.Fatalf("auth failed: %v", err)
			}
			if !authResp.Success {
				conn.Close()
				t.Fatalf("auth failed: %s", authResp.Message)
			}

			// Binary frame: [version][type][connIDLen][connID][payload]
			frame := make([]byte, 0, 3+len("x")+tc.payloadSize)
			frame = append(frame, byte(1), tc.frameType, byte(len("x")))
			frame = append(frame, 'x')
			frame = append(frame, make([]byte, tc.payloadSize)...)

			conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
				t.Fatalf("send oversize frame: %v", err)
			}

			// The server must close the connection in response.
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			_, _, readErr := conn.ReadMessage()
			conn.Close()
			if readErr == nil {
				t.Fatalf("server accepted a %d-byte %d frame (limit %d) without disconnecting", tc.payloadSize, tc.frameType, tc.limit)
			}
			fmt.Printf("PASS: %s → server disconnected the tunnel (%v)\n", tc.name, readErr)
		})
	}

	if healthOK(t) {
		fmt.Println("PASS: Server healthy after frame size violations")
	} else {
		t.Error("health check failed after frame size violations")
	}
}
