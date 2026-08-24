package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maborak/mabo-tunnel/internal/protocol"

	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"
)

const (
	maxWorkers     = 100
	maxQueueSize   = 500
	clientPongWait = 90 * time.Second

	// respChunkSize is how much response body is forwarded per frame. The
	// tunnel is a single connection shared by every in-flight request, so
	// smaller chunks yield the write lock more often and keep one large
	// download from starving the small requests queued behind it.
	respChunkSize = 16 * 1024

	// wsBufferSize sizes the WebSocket read/write buffers so a body chunk
	// leaves in one or two socket writes rather than a dozen.
	wsBufferSize = 64 * 1024

	// tunnelWriteTimeout bounds a single write to the tunnel. Long enough to
	// ride out congestion on a slow uplink, short enough that a dead peer is
	// noticed.
	tunnelWriteTimeout = 20 * time.Second

	// inspectorBodyLimit caps how much of each body the dashboard retains.
	inspectorBodyLimit = 64 * 1024

	// stableConnection is how long a tunnel must stay up before the reconnect
	// backoff is considered recovered and resets to its initial delay.
	stableConnection = 30 * time.Second
)

// errNotConnected is returned when a write is attempted with no live tunnel.
var errNotConnected = errors.New("tunnel connection closed")

// Config holds client configuration.
type Config struct {
	ServerURL     string
	Token         string
	LocalHost     string // forward target host (default: "localhost")
	LocalPort     int
	Subdomain     string
	Name          string
	Protocol      string            // "http" (default) or "tcp"
	BasicAuth     string            // "user:pass" — HTTP Basic Auth on the tunnel
	HeadersAdd    map[string]string // headers to add/override on proxied requests
	HeadersRemove []string          // headers to remove from proxied requests
}

// pendingRequest is a proxied request handed from the read loop to a worker:
// the request head, plus the pipe its body streams through.
type pendingRequest struct {
	connID string
	head   []byte
	body   *bodyPipe
}

// Client is the Mabo Tunnel client.
type Client struct {
	config         Config
	conn           atomic.Pointer[websocket.Conn]
	writeMu        sync.Mutex
	binary         atomic.Bool // server negotiated binary data frames
	tunnelID       string
	tunnelProtocol string // "http" or "tcp" as negotiated with server
	url            string
	sessionID      string
	color          string // assigned display color
	logger         *slog.Logger
	display        *Display
	inspector      *Inspector
	dashboard      *LocalDashboard
	policy         ReconnectPolicy
	httpClient     *http.Client // shared HTTP client with connection pooling and HTTP/2 support
	localConns     sync.Map     // connID → *localConn (TCP tunnels and WebSocket passthrough)
	reqBodies      sync.Map     // connID → *bodyPipe for in-flight request uploads
	reqCancels     sync.Map     // connID → context.CancelFunc for in-flight HTTP proxy requests
	OnReady        func(tunnelURL string)
}

// New creates a new Client instance.
func New(cfg Config, display *Display, inspector *Inspector, dashboard *LocalDashboard) *Client {
	b := make([]byte, 8)
	rand.Read(b)
	sid := hex.EncodeToString(b)

	// Create a shared transport with connection pooling.
	// Supports HTTP/2 for HTTPS targets automatically via Go's default behavior.
	transport := &http.Transport{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{},
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2: true,
		// Bound the time the local backend has to produce response headers.
		// Once headers are in, the body can stream for as long as it needs
		// (SSE, LLM token streams, long-poll, etc.).
		ResponseHeaderTimeout: 60 * time.Second,
		// Disable automatic gzip on the transport. We are a transparent proxy:
		// the caller's own Accept-Encoding is forwarded and the backend's
		// encoding must reach it untouched. Compression on the tunnel hop is
		// handled by permessage-deflate on the WebSocket instead.
		DisableCompression: true,
	}

	// Explicitly configure HTTP/2 on the transport so it works for both
	// HTTPS (native HTTP/2) and allows the transport to negotiate h2.
	http2.ConfigureTransport(transport)

	return &Client{
		config:    cfg,
		sessionID: sid,
		display:   display,
		inspector: inspector,
		dashboard: dashboard,
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelWarn, // suppress info logs — display handles output
		})),
		policy: DefaultReconnectPolicy(),
		httpClient: &http.Client{
			// No overall Timeout: streaming responses (SSE, LLM generation)
			// may legitimately hold the connection open for many minutes.
			// First-byte is bounded by ResponseHeaderTimeout; idle streams
			// are bounded by read deadlines on the body.
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// localTarget returns the host:port to forward to.
func (c *Client) localTarget() string {
	host := c.config.LocalHost
	if host == "" {
		host = "localhost"
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", c.config.LocalPort))
}

// URL returns the public tunnel URL.
func (c *Client) URL() string {
	return c.url
}

// Run connects to the server and starts forwarding. Blocks until context is canceled.
func (c *Client) Run(ctx context.Context) error {
	attempt := 0
	for {
		start := time.Now()
		err := c.connectAndServe(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// A connection that stayed up is evidence the problem passed. Without
		// this the backoff only ever grows, so a handful of brief glitches over
		// a long session pin every later reconnect at the 60s ceiling.
		if time.Since(start) >= stableConnection {
			attempt = 0
		}

		delay := c.policy.NextDelay(attempt)
		c.display.LogConnectionError(c.config.LocalPort,
			fmt.Sprintf("connection lost (%v), reconnecting in %s...", err, delay.Round(time.Millisecond)))
		attempt++
		if c.policy.MaxRetries > 0 && attempt >= c.policy.MaxRetries {
			return fmt.Errorf("max retries (%d) exceeded: %w", c.policy.MaxRetries, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

func (c *Client) connectAndServe(ctx context.Context) error {
	connectURL := c.config.ServerURL + "/tunnel/connect"
	if c.config.Subdomain != "" {
		connectURL += "?subdomain=" + url.QueryEscape(c.config.Subdomain)
	}

	dialer := websocket.Dialer{
		HandshakeTimeout:  15 * time.Second,
		ReadBufferSize:    wsBufferSize,
		WriteBufferSize:   wsBufferSize,
		EnableCompression: true,
	}
	conn, _, err := dialer.Dial(connectURL, nil)
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}
	c.conn.Store(conn)
	defer func() {
		conn.Close()
		c.conn.Store(nil)
		c.teardownConns()
	}()

	conn.SetReadLimit(16 * 1024 * 1024)

	if err := c.authenticate(conn); err != nil {
		return fmt.Errorf("auth: %w", err)
	}

	// Register tunnel in display and get assigned color.
	c.color = c.display.AddTunnel(c.url, c.config.LocalPort, c.config.Name, c.localTarget())

	// Register in local dashboard.
	if c.dashboard != nil {
		c.dashboard.AddTunnel(c.tunnelID, c.url, c.config.LocalPort, c.config.Name)
	}

	if c.OnReady != nil {
		c.OnReady(c.url)
	}

	return c.readLoop(ctx, conn)
}

// teardownConns closes everything tied to a tunnel connection that just ended.
func (c *Client) teardownConns() {
	c.localConns.Range(func(key, value any) bool {
		if lc, ok := value.(*localConn); ok {
			lc.Close()
		}
		c.localConns.Delete(key)
		return true
	})
	c.reqBodies.Range(func(key, value any) bool {
		if bp, ok := value.(*bodyPipe); ok {
			bp.CloseWithError(errNotConnected)
		}
		c.reqBodies.Delete(key)
		return true
	})
	c.reqCancels.Range(func(key, value any) bool {
		if cancel, ok := value.(context.CancelFunc); ok {
			cancel()
		}
		c.reqCancels.Delete(key)
		return true
	})
}

func (c *Client) authenticate(conn *websocket.Conn) error {
	authReq := protocol.AuthRequest{
		Token:     c.config.Token,
		Subdomain: c.config.Subdomain,
		SessionID: c.sessionID,
		Name:      c.config.Name,
		Protocol:  c.config.Protocol,
		BasicAuth: c.config.BasicAuth,
		Binary:    true,
	}

	env, err := protocol.NewEnvelope(protocol.TypeAuthRequest, &authReq)
	if err != nil {
		return fmt.Errorf("create auth envelope: %w", err)
	}

	msgBytes, err := env.Marshal()
	if err != nil {
		return fmt.Errorf("marshal auth: %w", err)
	}

	c.writeMu.Lock()
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err = conn.WriteMessage(websocket.TextMessage, msgBytes)
	conn.SetWriteDeadline(time.Time{})
	c.writeMu.Unlock()
	if err != nil {
		return fmt.Errorf("send auth: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, msg, err := conn.ReadMessage()
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}

	respEnv, err := protocol.ParseEnvelope(msg)
	if err != nil {
		return fmt.Errorf("parse auth response: %w", err)
	}

	if respEnv.Type != protocol.TypeAuthResponse {
		return fmt.Errorf("expected auth_response, got %s", respEnv.Type)
	}

	var authResp protocol.AuthResponse
	if err := respEnv.ParsePayload(&authResp); err != nil {
		return fmt.Errorf("parse auth response payload: %w", err)
	}

	if !authResp.Success {
		return fmt.Errorf("authentication failed: %s", authResp.Message)
	}

	c.tunnelID = authResp.TunnelID
	c.url = authResp.URL
	c.tunnelProtocol = authResp.Protocol
	if c.tunnelProtocol == "" {
		c.tunnelProtocol = protocol.ProtocolHTTP
	}
	// Only send binary frames if the server confirmed it understands them, so
	// a new client still works against an older server.
	c.binary.Store(authResp.Binary)
	if authResp.Username != "" {
		c.display.SetUsername(authResp.Username)
	}
	return nil
}

func (c *Client) readLoop(ctx context.Context, conn *websocket.Conn) error {
	requestCh := make(chan *pendingRequest, maxQueueSize)
	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range requestCh {
				c.handleRequest(ctx, req)
			}
		}()
	}
	defer func() {
		// Order matters: closing the channel tells workers to finish, but a
		// worker blocked streaming a quiet response (SSE with nothing to say)
		// only unblocks when its request context is canceled. Cancel FIRST,
		// then wait — teardownConns before wg.Wait is what lets this
		// connection actually end and the reconnect loop run.
		close(requestCh)
		c.teardownConns()
		// Drop the dying connection reference so worker cleanup writes fail
		// fast instead of each riding a 20s write deadline.
		c.conn.Store(nil)
		wg.Wait()
	}()

	conn.SetReadDeadline(time.Now().Add(clientPongWait))

	// Handle server pings — reset read deadline.
	conn.SetPingHandler(func(msg string) error {
		conn.SetReadDeadline(time.Now().Add(clientPongWait))
		c.writeMu.Lock()
		err := conn.WriteControl(websocket.PongMessage, []byte(msg), time.Now().Add(5*time.Second))
		c.writeMu.Unlock()
		return err
	})

	// Handle pong responses to our pings — measure round-trip latency.
	var pingSent sync.Map // stores time.Time by ping payload
	conn.SetPongHandler(func(msg string) error {
		conn.SetReadDeadline(time.Now().Add(clientPongWait))
		if sentAt, ok := pingSent.LoadAndDelete(msg); ok {
			rtt := time.Since(sentAt.(time.Time))
			c.display.UpdatePing(rtt.Milliseconds())
		}
		return nil
	})

	// connCtx is canceled when this connection ends, stopping goroutines.
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	// Send our own pings every 10s to measure RTT.
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		seq := 0
		for {
			select {
			case <-connCtx.Done():
				return
			case <-ticker.C:
				seq++
				payload := fmt.Sprintf("p%d", seq)
				pingSent.Store(payload, time.Now())
				c.writeMu.Lock()
				err := conn.WriteControl(websocket.PingMessage, []byte(payload), time.Now().Add(5*time.Second))
				c.writeMu.Unlock()
				if err != nil {
					return
				}
			}
		}
	}()

	go func() {
		<-connCtx.Done()
		// Only send graceful close if the parent context was canceled (user quit),
		// not if the connection just dropped.
		if ctx.Err() != nil {
			gracefulEnv, _ := protocol.NewEnvelope(protocol.TypeClose, &protocol.CloseFrame{
				TunnelID: c.tunnelID,
				Reason:   "graceful",
			})
			if gracefulMsg, err := gracefulEnv.Marshal(); err == nil {
				c.writeMu.Lock()
				conn.WriteMessage(websocket.TextMessage, gracefulMsg)
				c.writeMu.Unlock()
			}
			c.writeMu.Lock()
			conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "client shutting down"))
			c.writeMu.Unlock()
		}
		conn.Close()
	}()

	for {
		msgType, msg, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read message: %w", err)
		}

		// The payload of a binary frame aliases the buffer gorilla allocated
		// for this message. That buffer is not reused across reads, so it can
		// be handed onward without a copy.
		if msgType == websocket.BinaryMessage {
			frameType, connID, payload, decErr := protocol.DecodeBinaryFrame(msg)
			if decErr != nil {
				continue
			}
			if err := checkFrameSize(frameName(frameType), payload); err != nil {
				return fmt.Errorf("tunnel peer sent oversize frame: %w", err)
			}
			switch frameType {
			case protocol.BinTypeData:
				c.dispatchData(connID, payload, requestCh)
			case protocol.BinTypeReqBody:
				c.dispatchReqBody(connID, payload)
			case protocol.BinTypeReqEnd:
				c.dispatchReqEnd(connID)
			case protocol.BinTypeTCPData:
				c.dispatchTCPData(connID, payload)
			}
			continue
		}

		env, err := protocol.ParseEnvelope(msg)
		if err != nil {
			continue
		}

		switch env.Type {
		case protocol.TypeData:
			var frame protocol.DataFrame
			if err := env.ParsePayload(&frame); err != nil {
				continue
			}
			if err := checkFrameSize("data", frame.Data); err != nil {
				return fmt.Errorf("tunnel peer sent oversize frame: %w", err)
			}
			c.dispatchData(frame.ConnID, frame.Data, requestCh)

		case protocol.TypeReqBody:
			var frame protocol.DataFrame
			if err := env.ParsePayload(&frame); err != nil {
				continue
			}
			if err := checkFrameSize("req_body", frame.Data); err != nil {
				return fmt.Errorf("tunnel peer sent oversize frame: %w", err)
			}
			c.dispatchReqBody(frame.ConnID, frame.Data)

		case protocol.TypeReqEnd:
			var frame protocol.CloseFrame
			if err := env.ParsePayload(&frame); err != nil {
				continue
			}
			c.dispatchReqEnd(frame.ConnID)

		case protocol.TypeTCPData:
			var frame protocol.DataFrame
			if err := env.ParsePayload(&frame); err != nil {
				continue
			}
			if err := checkFrameSize("tcp_data", frame.Data); err != nil {
				return fmt.Errorf("tunnel peer sent oversize frame: %w", err)
			}
			c.dispatchTCPData(frame.ConnID, frame.Data)

		case protocol.TypeClose:
			var closeFrame protocol.CloseFrame
			if err := env.ParsePayload(&closeFrame); err != nil {
				continue
			}
			switch closeFrame.Reason {
			case protocol.CloseReasonTCPEOF:
				c.closeLocalConn(closeFrame.ConnID)
			case protocol.CloseReasonCancel:
				// Server is telling us the public caller went away —
				// abort the in-flight upstream request if any.
				if val, ok := c.reqCancels.LoadAndDelete(closeFrame.ConnID); ok {
					val.(context.CancelFunc)()
				}
				if val, ok := c.reqBodies.LoadAndDelete(closeFrame.ConnID); ok {
					val.(*bodyPipe).CloseWithError(context.Canceled)
				}
				// Also tear down an active WS passthrough conn if any.
				c.closeLocalConn(closeFrame.ConnID)
			}

		case protocol.TypeNotice:
			var notice protocol.Notice
			if err := env.ParsePayload(&notice); err != nil {
				continue
			}
			c.handleNotice(&notice)

		case protocol.TypePong:
			// Application-level pong.
		}
	}
}

// checkFrameSize enforces the protocol's per-type payload limits on frames
// arriving from the server. The queues draining these frames are sized for
// the documented chunk sizes; an oversize frame from a hostile or broken
// server tears down the connection (the reconnect loop handles the rest)
// rather than parking megabytes.
func checkFrameSize(name string, payload []byte) error {
	limit := protocol.MaxStreamChunkBytes
	if name == "data" {
		// A data frame carries the request head (up to net/http's header
		// limit) or WebSocket passthrough chunks.
		limit = protocol.MaxRequestHeadBytes
	}
	if len(payload) > limit {
		return fmt.Errorf("%s payload %d bytes exceeds protocol limit %d", name, len(payload), limit)
	}
	return nil
}

// frameName maps a binary frame type to the name used in size-limit errors.
func frameName(frameType byte) string {
	switch frameType {
	case protocol.BinTypeData:
		return "data"
	case protocol.BinTypeReqBody:
		return "req_body"
	case protocol.BinTypeTCPData:
		return "tcp_data"
	default:
		return fmt.Sprintf("binary(%d)", frameType)
	}
}

// dispatchData routes a data frame: either bytes for an established passthrough
// connection, or the head of a new proxied request.
func (c *Client) dispatchData(connID string, data []byte, requestCh chan<- *pendingRequest) {
	if val, ok := c.localConns.Load(connID); ok {
		if !val.(*localConn).Send(data) {
			c.localConns.Delete(connID)
		}
		return
	}

	// New request. The body pipe is created here, on the read loop, so that
	// body frames arriving immediately behind the head always find it.
	body := newBodyPipe(inspectorBodyLimit)
	c.reqBodies.Store(connID, body)

	select {
	case requestCh <- &pendingRequest{connID: connID, head: data, body: body}:
	default:
		c.reqBodies.Delete(connID)
		body.CloseWithError(errors.New("client overloaded"))
		go func() {
			headers := map[string][]string{
				"Content-Type": {"text/plain; charset=utf-8"},
			}
			if err := c.sendRespHeader(connID, http.StatusServiceUnavailable, headers); err == nil {
				_ = c.sendRespBody(connID, []byte("Client overloaded"))
				c.sendRespEnd(connID, "")
			}
		}()
	}
}

// dispatchReqBody hands an upload chunk to the in-flight request's body pipe.
func (c *Client) dispatchReqBody(connID string, data []byte) {
	if val, ok := c.reqBodies.Load(connID); ok {
		if !val.(*bodyPipe).Send(data) {
			c.reqBodies.Delete(connID)
		}
	}
}

// dispatchReqEnd signals a complete upload.
func (c *Client) dispatchReqEnd(connID string) {
	if val, ok := c.reqBodies.LoadAndDelete(connID); ok {
		val.(*bodyPipe).Close()
	}
}

// dispatchTCPData writes bytes to a local TCP connection, dialing it if this is
// the first frame. The connection slot is reserved before the dial so a second
// frame queues behind the first rather than opening a second socket.
func (c *Client) dispatchTCPData(connID string, data []byte) {
	if val, ok := c.localConns.Load(connID); ok {
		if !val.(*localConn).Send(data) {
			c.localConns.Delete(connID)
		}
		return
	}

	lc := newLocalConn()
	if actual, loaded := c.localConns.LoadOrStore(connID, lc); loaded {
		if !actual.(*localConn).Send(data) {
			c.localConns.Delete(connID)
		}
		return
	}

	lc.Send(data)
	go c.dialLocalTCP(connID, lc)
}

// dialLocalTCP connects a reserved TCP connection slot to the local server and
// starts pumping its output back through the tunnel.
func (c *Client) dialLocalTCP(connID string, lc *localConn) {
	conn, err := net.DialTimeout("tcp", c.localTarget(), 10*time.Second)
	if err != nil {
		c.logger.Error("failed to dial local TCP", "error", err, "conn_id", connID, "local_addr", c.localTarget())
		lc.Close()
		c.localConns.Delete(connID)
		c.sendClose(connID, protocol.CloseReasonTCPEOF)
		return
	}
	lc.Attach(conn)
	c.tcpLocalReadLoop(connID, conn)
}

// closeLocalConn tears down a local connection by ID.
func (c *Client) closeLocalConn(connID string) {
	if val, ok := c.localConns.LoadAndDelete(connID); ok {
		val.(*localConn).Close()
	}
}

// handleNotice surfaces an out-of-band server notice in the TUI.
func (c *Client) handleNotice(n *protocol.Notice) {
	method := n.Method
	if method == "" {
		method = "???"
	}
	path := n.Path
	if path == "" {
		path = "/"
	}
	c.display.LogError(c.color, c.config.LocalPort, method, path, n.Message)
}

// handleRequest proxies one request to the local server and streams the
// response back through the tunnel.
func (c *Client) handleRequest(ctx context.Context, pr *pendingRequest) {
	defer func() {
		if r := recover(); r != nil {
			c.display.LogError(c.color, c.config.LocalPort, "???", "/", fmt.Sprintf("panic: %v", r))
		}
	}()

	start := time.Now()

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(pr.head)))
	if err != nil {
		c.display.LogError(c.color, c.config.LocalPort, "???", "/", "failed to parse request")
		c.sendRespError(pr.connID, "failed to parse request")
		c.discardBody(pr)
		return
	}

	method := req.Method
	path := req.URL.Path

	// Detect WebSocket upgrade and hand it to its own goroutine. A passthrough
	// lives as long as the socket does; holding a pool worker for it would let
	// a hundred browser WebSockets starve every HTTP request on this tunnel.
	if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") {
		c.discardBody(pr)
		go c.handleWebSocketPassthrough(ctx, pr.connID, pr.head, req)
		return
	}

	// Copy request headers before proxying (for inspector).
	reqHeaders := make(map[string][]string, len(req.Header))
	for k, v := range req.Header {
		copied := make([]string, len(v))
		copy(copied, v)
		reqHeaders[k] = copied
	}

	localURL := &url.URL{
		Scheme:   "http",
		Host:     c.localTarget(),
		Path:     req.URL.Path,
		RawPath:  req.URL.RawPath,
		RawQuery: req.URL.RawQuery,
	}

	// Per-request context so the server can cancel in-flight upstream
	// requests by sending a close frame with reason=cancel.
	reqCtx, cancel := context.WithCancel(ctx)
	c.reqCancels.Store(pr.connID, context.CancelFunc(cancel))
	defer func() {
		c.reqCancels.Delete(pr.connID)
		cancel()
	}()

	// The body streams straight through from the tunnel — it is never buffered
	// whole on the way in.
	var bodyReader io.Reader
	if req.ContentLength != 0 {
		bodyReader = pr.body
	} else {
		c.discardBody(pr)
	}

	proxyReq, err := http.NewRequestWithContext(reqCtx, req.Method, localURL.String(), bodyReader)
	if err != nil {
		c.display.LogError(c.color, c.config.LocalPort, method, path, "failed to create request")
		c.sendRespError(pr.connID, "failed to create request")
		return
	}
	proxyReq.ContentLength = req.ContentLength

	for key, vals := range req.Header {
		if protocol.HopByHopHeaders[key] {
			continue
		}
		for _, val := range vals {
			proxyReq.Header.Add(key, val)
		}
	}
	// X-Forwarded-For passes through untouched from the forwarded head: the
	// server appends the verified public origin to the chain before sending
	// it, so the local app reading the rightmost entry gets an address the
	// edge actually confirmed. Overwriting it here would erase that (and an
	// http.ReadRequest request has no RemoteAddr to write instead).
	proxyReq.Header.Set("X-Forwarded-Host", req.Host)
	proxyReq.Header.Set("X-Forwarded-Proto", "https")

	// Apply header manipulation: remove headers first, then add/override.
	for _, h := range c.config.HeadersRemove {
		proxyReq.Header.Del(strings.TrimSpace(h))
	}
	for k, v := range c.config.HeadersAdd {
		proxyReq.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(proxyReq)
	if err != nil {
		// If the request was canceled by the server (public caller gone),
		// don't spam the TUI with a synthetic 502 — the server already
		// closed the public connection.
		if reqCtx.Err() != nil {
			c.sendRespEnd(pr.connID, "canceled")
			return
		}
		c.display.LogError(c.color, c.config.LocalPort, method, path, err.Error())
		c.sendRespError(pr.connID, "Local server unreachable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	// Copy headers for both the outgoing header frame and the inspector.
	respHeaders := make(map[string][]string, len(resp.Header))
	for k, v := range resp.Header {
		copied := make([]string, len(v))
		copy(copied, v)
		respHeaders[k] = copied
	}

	// Send the header frame immediately so the public caller can start
	// receiving status/headers while the body is still being generated.
	if err := c.sendRespHeader(pr.connID, resp.StatusCode, respHeaders); err != nil {
		c.display.LogError(c.color, c.config.LocalPort, method, path, "tunnel write failed: "+err.Error())
		return
	}

	// Stream the body in chunks. We flush after every read so SSE / chunked
	// / LLM token streams reach the public caller incrementally.
	buf := make([]byte, respChunkSize)
	var inspectorBody bytes.Buffer
	streamErr := ""
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if err := c.sendRespBody(pr.connID, buf[:n]); err != nil {
				streamErr = "tunnel write failed: " + err.Error()
				break
			}
			if inspectorBody.Len() < inspectorBodyLimit {
				remaining := inspectorBodyLimit - inspectorBody.Len()
				if n > remaining {
					inspectorBody.Write(buf[:remaining])
				} else {
					inspectorBody.Write(buf[:n])
				}
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				streamErr = readErr.Error()
			}
			break
		}
	}

	c.sendRespEnd(pr.connID, streamErr)

	duration := time.Since(start)
	if streamErr != "" && reqCtx.Err() == nil {
		c.display.LogError(c.color, c.config.LocalPort, method, path, streamErr)
	} else {
		c.display.LogRequest(c.color, c.config.LocalPort, method, path, resp.StatusCode, duration)
	}

	// Record in inspector for local dashboard.
	if c.inspector != nil {
		// Derive scheme from X-Forwarded-Proto (set by reverse proxy like Caddy).
		scheme := "http"
		if proto := req.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		}
		fullURL := scheme + "://" + req.Host + req.URL.RequestURI()

		c.inspector.RecordFull(&CapturedRequest{
			TunnelID:        c.tunnelID,
			Method:          method,
			Path:            req.URL.RequestURI(),
			FullURL:         fullURL,
			Host:            req.Host,
			RequestHeaders:  reqHeaders,
			RequestBody:     string(pr.body.Captured()),
			ResponseStatus:  resp.StatusCode,
			ResponseHeaders: respHeaders,
			ResponseBody:    inspectorBody.String(),
			Duration:        duration,
		})
	}
}

// discardBody releases a request body pipe that will never be read.
func (c *Client) discardBody(pr *pendingRequest) {
	c.reqBodies.Delete(pr.connID)
	pr.body.Close()
}

// wsUpgradeTimeout bounds how long the local server has to answer the
// WebSocket upgrade. Mirrors the server-side upgrade wait: a local backend
// that accepts the TCP connection but never answers the upgrade must not
// hold a goroutine and a socket open indefinitely.
const wsUpgradeTimeout = 30 * time.Second

// handleWebSocketPassthrough dials the local WebSocket server and bidirectionally
// streams raw bytes between the tunnel and the local server.
func (c *Client) handleWebSocketPassthrough(ctx context.Context, connID string, head []byte, req *http.Request) {
	path := req.URL.Path

	c.display.LogRequest(c.color, c.config.LocalPort, "WS", path, 101, 0)

	// Dial the local server as a raw TCP connection so we can forward the
	// WebSocket upgrade verbatim (including all headers).
	localAddr := c.localTarget()
	localConnRaw, err := net.DialTimeout("tcp", localAddr, 10*time.Second)
	if err != nil {
		c.display.LogError(c.color, c.config.LocalPort, "WS", path, "local dial failed: "+err.Error())
		c.sendData(connID, []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nLocal WebSocket server unreachable"))
		return
	}
	defer localConnRaw.Close()

	// Register the connection slot and its writer before anything is sent, so
	// a tunnel teardown during the upgrade reaches the socket instead of
	// leaving an unreachable goroutine behind.
	lc := newLocalConn()
	lc.Attach(localConnRaw)
	c.localConns.Store(connID, lc)
	defer func() {
		c.localConns.Delete(connID)
		lc.Close()
		// Tell the server the local side is finished, mirroring the TCP
		// tunnels: without this the public WebSocket stays open with a dead
		// local peer behind it. Harmless if the tunnel is already gone.
		c.sendClose(connID, protocol.CloseReasonTCPEOF)
	}()

	// Forward the original upgrade request bytes to the local server through
	// the writer so ordering with any tunnel frames is preserved.
	if !lc.Send(head) {
		c.display.LogError(c.color, c.config.LocalPort, "WS", path, "write upgrade failed")
		c.sendData(connID, []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nFailed to forward upgrade"))
		return
	}

	// Read the upgrade response from the local server and send it back.
	// We read the HTTP response first, then stream bidirectionally.
	localBuf := bufio.NewReader(localConnRaw)
	localConnRaw.SetReadDeadline(time.Now().Add(wsUpgradeTimeout))
	resp, err := http.ReadResponse(localBuf, req)
	localConnRaw.SetReadDeadline(time.Time{})
	if err != nil {
		c.display.LogError(c.color, c.config.LocalPort, "WS", path, "read upgrade response failed: "+err.Error())
		c.sendData(connID, []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nLocal server did not respond to upgrade"))
		return
	}

	rawResp, err := httputil.DumpResponse(resp, false)
	resp.Body.Close()
	if err != nil {
		c.display.LogError(c.color, c.config.LocalPort, "WS", path, "dump upgrade response failed: "+err.Error())
		return
	}

	// Send the upgrade response (101 Switching Protocols) back through the tunnel.
	c.sendData(connID, rawResp)

	// Local server → tunnel. Anything the local server buffered while we were
	// parsing the upgrade response is still in localBuf, so read through it.
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 32*1024)
		for {
			n, readErr := localBuf.Read(buf)
			if n > 0 {
				if err := c.sendData(connID, buf[:n]); err != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	// Wait for the local→tunnel goroutine to finish or context cancellation.
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// tcpLocalReadLoop reads data from a local TCP connection and sends it back
// through the WebSocket tunnel to the server.
func (c *Client) tcpLocalReadLoop(connID string, conn net.Conn) {
	defer func() {
		c.closeLocalConn(connID)
		c.sendClose(connID, protocol.CloseReasonTCPEOF)
	}()

	buf := make([]byte, 32*1024)
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			if sendErr := c.sendTCPData(connID, buf[:n]); sendErr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
			}
			return
		}
	}
}

// ── tunnel writes ───────────────────────────────────────────────────────────

// writeMessage sends one WebSocket message under the write lock.
func (c *Client) writeMessage(msgType int, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	conn := c.conn.Load()
	if conn == nil {
		return errNotConnected
	}
	conn.SetWriteDeadline(time.Now().Add(tunnelWriteTimeout))
	err := conn.WriteMessage(msgType, data)
	conn.SetWriteDeadline(time.Time{})
	return err
}

// writeEnvelope marshals and writes a JSON control message.
func (c *Client) writeEnvelope(env *protocol.Envelope) error {
	msgBytes, err := env.Marshal()
	if err != nil {
		return err
	}
	return c.writeMessage(websocket.TextMessage, msgBytes)
}

// writeControl builds and sends a JSON control message.
func (c *Client) writeControl(msgType string, payload any) error {
	env, err := protocol.NewEnvelope(msgType, payload)
	if err != nil {
		return err
	}
	return c.writeEnvelope(env)
}

// writeData sends bulk bytes, using binary framing when the server negotiated
// it and falling back to the base64-in-JSON frame when it did not.
func (c *Client) writeData(binType byte, jsonType, connID string, payload []byte) error {
	if c.binary.Load() {
		buf, err := protocol.EncodeBinaryFrame(binType, connID, payload)
		if err != nil {
			return err
		}
		return c.writeMessage(websocket.BinaryMessage, buf)
	}
	return c.writeControl(jsonType, &protocol.DataFrame{
		ConnID:   connID,
		TunnelID: c.tunnelID,
		Data:     payload,
	})
}

// sendData forwards WebSocket passthrough bytes.
func (c *Client) sendData(connID string, data []byte) error {
	return c.writeData(protocol.BinTypeData, protocol.TypeData, connID, data)
}

// sendTCPData forwards raw TCP bytes.
func (c *Client) sendTCPData(connID string, data []byte) error {
	return c.writeData(protocol.BinTypeTCPData, protocol.TypeTCPData, connID, data)
}

// sendRespBody sends a single chunk of streaming response body.
func (c *Client) sendRespBody(connID string, data []byte) error {
	return c.writeData(protocol.BinTypeRespBody, protocol.TypeRespBody, connID, data)
}

// sendRespHeader sends the streaming response's status code + headers frame.
func (c *Client) sendRespHeader(connID string, status int, headers map[string][]string) error {
	return c.writeControl(protocol.TypeRespHeader, &protocol.RespHeaderFrame{
		ConnID:     connID,
		TunnelID:   c.tunnelID,
		StatusCode: status,
		Headers:    headers,
	})
}

// sendRespEnd signals end-of-stream for a proxied HTTP response. reason is
// empty on clean EOF, otherwise it carries an upstream error description.
func (c *Client) sendRespEnd(connID, reason string) {
	_ = c.writeControl(protocol.TypeRespEnd, &protocol.CloseFrame{
		ConnID:   connID,
		TunnelID: c.tunnelID,
		Reason:   reason,
	})
}

// sendClose tells the server a logical connection ended.
func (c *Client) sendClose(connID, reason string) {
	_ = c.writeControl(protocol.TypeClose, &protocol.CloseFrame{
		ConnID:   connID,
		TunnelID: c.tunnelID,
		Reason:   reason,
	})
}

// sendRespError is a convenience: emits a synthetic 502 header + body + end
// frames for failures that happen before we have a real upstream response.
func (c *Client) sendRespError(connID, msg string) {
	headers := map[string][]string{
		"Content-Type": {"text/plain; charset=utf-8"},
	}
	if err := c.sendRespHeader(connID, http.StatusBadGateway, headers); err != nil {
		return
	}
	_ = c.sendRespBody(connID, []byte(msg))
	c.sendRespEnd(connID, "")
}
