package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/maborak/mabo-tunnel/internal/auth"
	"github.com/maborak/mabo-tunnel/internal/protocol"
	"github.com/maborak/mabo-tunnel/internal/version"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"

	"github.com/gorilla/websocket"
)

const (
	// WebSocket keepalive interval.
	pingInterval = 25 * time.Second
	// How long to wait for a pong before considering the connection dead.
	pongWait = 90 * time.Second
	// Max inbound WebSocket frame size (16 MB).
	maxMessageSize = 16 * 1024 * 1024
	// Max concurrent proxied requests per tunnel.
	maxProxiedPerTunnel = 200
	// WebSocket read/write buffer size. Large enough that a 32 KiB body chunk
	// leaves in one or two socket writes instead of eleven.
	wsBufferSize = 64 * 1024
)

// Config holds server configuration.
type Config struct {
	Addr       string
	Domain     string
	UsersFile  string
	TCPPortMin int // start of TCP port range for TCP tunnels (inclusive)
	TCPPortMax int // end of TCP port range for TCP tunnels (inclusive)

	// TrustedProxies lists CIDRs whose X-Forwarded-For header is believed.
	// Empty means loopback plus the private ranges.
	TrustedProxies []string

	// LogLevel is "debug", "info", "warn", or "error". Empty means info.
	LogLevel string

	// Keepalive tuning. Zero uses the defaults below. These exist so tests can
	// exercise ping/pong and idle timeout behavior in seconds rather than
	// sleeping through the production cadence.
	KeepaliveInterval time.Duration // ping cadence, default 25s
	KeepaliveTimeout  time.Duration // pong deadline, default 90s

	// Auth rate limiting. Zero uses the defaults: 5 attempts per minute.
	RateLimitMax    int
	RateLimitWindow time.Duration

	// UpstreamHeaderTimeout bounds how long a proxied request waits for the
	// local server's response headers. Once headers arrive there is no further
	// deadline, so a stream may run for as long as it needs. Zero means 60s.
	UpstreamHeaderTimeout time.Duration

	// AIO (all-in-one) mode: built-in HTTP + HTTPS + auto certs.
	AIO         bool
	AIOBind     string // bind IP (default: 0.0.0.0)
	AIOEmail    string // ACME email for Let's Encrypt
	AIOCFToken  string // Cloudflare API token for DNS-01 challenge
	AIOCertPath string // certificate storage directory

	// EmbeddedUsers holds users data decrypted at startup (same format as users.txt).
	// If non-empty, takes precedence over UsersFile.
	EmbeddedUsers string
}

// Server is the main Mabo Tunnel server.
type Server struct {
	config   Config
	tunnels  *TunnelManager
	users    *auth.UserStore
	limiter  *auth.RateLimiter
	proxy    *ProxyHandler
	logger   *slog.Logger
	mux      *http.ServeMux
	upgrader websocket.Upgrader

	// Resolved keepalive timings.
	pingInterval time.Duration
	pongWait     time.Duration
}

// parseLogLevel maps a config string onto a slog level.
func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// New creates a new Server instance.
func New(cfg Config) (*Server, error) {
	level := parseLogLevel(cfg.LogLevel)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
		// Source resolution costs a runtime.Caller on every record. Keep it
		// for debug runs, where the volume is intentional, not for production
		// where it sits on the per-request path.
		AddSource: level == slog.LevelDebug,
	}))

	var users *auth.UserStore
	var err error
	if cfg.EmbeddedUsers != "" {
		users, err = auth.NewUserStoreFromData(cfg.EmbeddedUsers)
		if err != nil {
			return nil, fmt.Errorf("parse embedded users: %w", err)
		}
		logger.Info("loaded embedded users", "count", users.Count())
	} else {
		users, err = auth.NewUserStore(cfg.UsersFile)
		if err != nil {
			return nil, fmt.Errorf("load users: %w", err)
		}
		logger.Info("loaded users", "count", users.Count(), "file", cfg.UsersFile)
	}

	// A plaintext entry means the user file (and any binary embedding it) still
	// holds a usable credential. Hashed entries do not.
	if n := users.PlaintextEntries(); n > 0 {
		logger.Warn("user file contains unhashed tokens — anyone who reads it can authenticate as those users",
			"plaintext_entries", n,
			"migrate_with", "mabo-tunnel-token migrate <users-file>",
		)
	}

	rateMax := cfg.RateLimitMax
	if rateMax == 0 {
		rateMax = 5
	}
	rateWindow := cfg.RateLimitWindow
	if rateWindow == 0 {
		rateWindow = time.Minute
	}
	limiter := auth.NewRateLimiter(rateMax, rateWindow)

	tcpMin := cfg.TCPPortMin
	tcpMax := cfg.TCPPortMax
	if tcpMin == 0 {
		tcpMin = 10000
	}
	if tcpMax == 0 {
		tcpMax = 10100
	}
	tunnels := NewTunnelManager(cfg.Domain, tcpMin, tcpMax, logger)
	proxy := NewProxyHandler(tunnels, cfg.Domain, cfg.TrustedProxies, cfg.UpstreamHeaderTimeout, logger)

	pingEvery := cfg.KeepaliveInterval
	if pingEvery == 0 {
		pingEvery = pingInterval
	}
	pongDeadline := cfg.KeepaliveTimeout
	if pongDeadline == 0 {
		pongDeadline = pongWait
	}

	s := &Server{
		config:       cfg,
		tunnels:      tunnels,
		users:        users,
		limiter:      limiter,
		proxy:        proxy,
		logger:       logger,
		pingInterval: pingEvery,
		pongWait:     pongDeadline,
		mux:          http.NewServeMux(),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  wsBufferSize,
			WriteBufferSize: wsBufferSize,
			CheckOrigin:     func(r *http.Request) bool { return true },
			// permessage-deflate. Tunneled payloads are mostly text (HTML,
			// JSON, SSE) and the client's uplink is usually the bottleneck.
			EnableCompression: true,
		},
	}

	s.mux.HandleFunc("/tunnel/connect", s.handleTunnelConnect)
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/ready", s.handleReady)
	s.mux.HandleFunc("/", s.handleRoot)

	// Dashboard and API are served locally on the CLIENT side (localhost:4040).

	return s, nil
}

// effectiveScheme reports the scheme public tunnel URLs are advertised with.
// Only AIO mode terminates TLS itself; a plain-mode server sits behind a
// reverse proxy (see docs/deployment.md) and its URLs are honest about that.
func (s *Server) effectiveScheme() string {
	if s.config.AIO {
		return "https"
	}
	return "http"
}

// newHTTPServer builds an http.Server with timeouts suited to a tunnel edge.
//
// There is deliberately no WriteTimeout: a proxied response may legitimately
// stream for many minutes (SSE, LLM generation, large downloads), and
// WriteTimeout would cut it off mid-body regardless of activity. Time-to-first
// -byte is bounded per request in streamResponse instead. ReadHeaderTimeout
// bounds slowloris without capping upload duration.
func (s *Server) newHTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// Run starts the server and blocks until the context is canceled.
func (s *Server) Run(ctx context.Context) error {
	if s.config.AIO {
		return s.runAIO(ctx)
	}
	return s.runPlain(ctx)
}

// shutdown tears down shared background workers.
func (s *Server) shutdown() {
	s.tunnels.DrainAll()
	s.tunnels.Stop()
	s.limiter.Stop()
}

// Close releases a Server's background workers. Run does this itself on
// shutdown; Close is for callers that mount the Server as an http.Handler
// without ever calling Run, which is how the tests drive it.
func (s *Server) Close() {
	s.shutdown()
}

// runPlain starts the plain HTTP server (original behavior, for use behind a reverse proxy).
func (s *Server) runPlain(ctx context.Context) error {
	httpServer := s.newHTTPServer(s.config.Addr)

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("server starting", "addr", s.config.Addr, "domain", s.config.Domain, "version", version.Version)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("shutting down server")
		s.shutdown()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// runAIO starts the all-in-one server: HTTP on :80, HTTPS on :443 with auto Let's Encrypt certs.
func (s *Server) runAIO(ctx context.Context) error {
	// Configure CertMagic storage.
	certmagic.Default.Storage = &certmagic.FileStorage{Path: s.config.AIOCertPath}

	// Configure ACME issuer with DNS-01 challenge via Cloudflare.
	certmagic.DefaultACME.Email = s.config.AIOEmail
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: &cloudflare.Provider{
				APIToken: s.config.AIOCFToken,
			},
		},
	}

	// Manage certificates for the domain and wildcard.
	magic := certmagic.NewDefault()
	domains := []string{s.config.Domain, "*." + s.config.Domain}
	s.logger.Info("provisioning TLS certificates", "domains", domains)
	if err := magic.ManageSync(ctx, domains); err != nil {
		return fmt.Errorf("certmagic: %w", err)
	}
	s.logger.Info("TLS certificates ready")

	// Build TLS config from CertMagic.
	tlsConfig := magic.TLSConfig()
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}

	bind := s.config.AIOBind
	httpAddr := bind + ":80"
	httpsAddr := bind + ":443"

	httpServer := s.newHTTPServer(httpAddr)
	httpsServer := s.newHTTPServer(httpsAddr)
	httpsServer.TLSConfig = tlsConfig

	errCh := make(chan error, 2)
	go func() {
		s.logger.Info("AIO HTTP server starting", "addr", httpAddr, "domain", s.config.Domain, "version", version.Version)
		errCh <- httpServer.ListenAndServe()
	}()
	go func() {
		s.logger.Info("AIO HTTPS server starting", "addr", httpsAddr, "domain", s.config.Domain, "version", version.Version)
		errCh <- httpsServer.ListenAndServeTLS("", "")
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("shutting down AIO server")
		s.shutdown()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdownCtx)
		httpsServer.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

// ServeHTTP routes requests: subdomain requests go to the proxy, everything else to the mux.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := hostWithoutPort(r.Host)

	if strings.HasSuffix(host, "."+s.config.Domain) {
		s.proxy.ServeHTTP(w, r)
		return
	}

	s.mux.ServeHTTP(w, r)
}

// handleTunnelConnect handles WebSocket tunnel connections from clients.
func (s *Server) handleTunnelConnect(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("websocket upgrade failed", "error", err)
		return
	}

	// Set max message size.
	conn.SetReadLimit(maxMessageSize)

	remoteAddr := s.proxy.extractClientIP(r)

	// Authenticate the client.
	ar := handleAuth(conn, s.users, s.limiter, remoteAddr, s.logger)
	if ar == nil {
		conn.Close()
		return
	}

	// Query param subdomain overrides protocol-level one.
	subdomain := r.URL.Query().Get("subdomain")
	if subdomain == "" {
		subdomain = ar.Subdomain
	}

	// Determine protocol: default to HTTP.
	tunnelProtocol := r.URL.Query().Get("protocol")
	if tunnelProtocol == "" {
		tunnelProtocol = ar.Protocol
	}
	if tunnelProtocol == "" {
		tunnelProtocol = protocol.ProtocolHTTP
	}

	opts := RegisterOpts{
		Conn:       conn,
		Username:   ar.User.Username,
		Plan:       ar.User.Plan,
		Subdomain:  subdomain,
		SessionID:  ar.SessionID,
		Name:       ar.Name,
		AllowedIPs: ar.AllowedIPs,
		DeniedIPs:  ar.DeniedIPs,
		BasicAuth:  ar.BasicAuth,
		Binary:     ar.Binary,
	}

	var tunnel *Tunnel
	switch tunnelProtocol {
	case protocol.ProtocolTCP:
		var err error
		tunnel, err = s.tunnels.RegisterTCP(opts)
		if err != nil {
			s.logger.Error("failed to register TCP tunnel", "error", err, "username", ar.User.Username)
			sendAuthResponse(conn, false, err.Error(), nil)
			conn.Close()
			return
		}

		tunnelURL := fmt.Sprintf("tcp://%s:%d", s.config.Domain, tunnel.TCPPort)
		s.logger.Info("TCP tunnel registered",
			"tunnel_id", tunnel.ID,
			"subdomain", tunnel.Subdomain,
			"tcp_port", tunnel.TCPPort,
			"session_id", ar.SessionID,
			"url", tunnelURL,
			"username", ar.User.Username,
			"binary", tunnel.Binary,
		)

		// Register already published this tunnel, so a public request can be
		// writing to the same socket right now. Send the auth response through
		// the tunnel's write lock, not straight at the connection.
		if err := tunnel.WriteControl(protocol.TypeAuthResponse, &protocol.AuthResponse{
			Success:   true,
			TunnelID:  tunnel.ID,
			Subdomain: tunnel.Subdomain,
			URL:       tunnelURL,
			Username:  ar.User.Username,
			Protocol:  protocol.ProtocolTCP,
			TCPPort:   tunnel.TCPPort,
			Binary:    tunnel.Binary,
		}); err != nil {
			s.logger.Error("failed to send auth response", "error", err, "tunnel_id", tunnel.ID)
			s.tunnels.Unregister(tunnel.ID)
			conn.Close()
			return
		}

		// Start TCP proxy to accept connections and forward through the tunnel.
		tcpProxy := NewTCPProxy(tunnel, s.logger)
		go tcpProxy.Serve()

	default:
		// HTTP tunnel (existing behavior).
		var err error
		tunnel, err = s.tunnels.Register(opts)
		if err != nil {
			s.logger.Error("failed to register tunnel", "error", err, "username", ar.User.Username)
			sendAuthResponse(conn, false, err.Error(), nil)
			conn.Close()
			return
		}

		tunnel.Protocol = protocol.ProtocolHTTP
		tunnelURL := s.tunnels.URL(tunnel.Subdomain, s.effectiveScheme())
		s.logger.Info("tunnel registered",
			"tunnel_id", tunnel.ID,
			"subdomain", tunnel.Subdomain,
			"session_id", ar.SessionID,
			"url", tunnelURL,
			"username", ar.User.Username,
			"binary", tunnel.Binary,
		)

		// Same as above: the tunnel is already reachable, so this write has to
		// take the tunnel's write lock.
		if err := tunnel.WriteControl(protocol.TypeAuthResponse, &protocol.AuthResponse{
			Success:   true,
			TunnelID:  tunnel.ID,
			Subdomain: tunnel.Subdomain,
			URL:       tunnelURL,
			Username:  ar.User.Username,
			Protocol:  protocol.ProtocolHTTP,
			Binary:    tunnel.Binary,
		}); err != nil {
			s.logger.Error("failed to send auth response", "error", err, "tunnel_id", tunnel.ID)
			s.tunnels.Unregister(tunnel.ID)
			conn.Close()
			return
		}
	}

	// Start read loop and ping loop.
	go s.tunnelPingLoop(tunnel)
	go s.tunnelReadLoop(tunnel)
}

// tunnelPingLoop sends periodic pings to keep the connection alive.
func (s *Server) tunnelPingLoop(tunnel *Tunnel) {
	ticker := time.NewTicker(s.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-tunnel.done:
			return
		case <-ticker.C:
			tunnel.writeMu.Lock()
			tunnel.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			err := tunnel.Conn.WriteMessage(websocket.PingMessage, nil)
			tunnel.Conn.SetWriteDeadline(time.Time{})
			tunnel.writeMu.Unlock()

			if err != nil {
				s.logger.Error("ping failed", "error", err, "tunnel_id", tunnel.ID)
				return
			}
		}
	}
}

// tunnelReadLoop reads messages from the client WebSocket and dispatches them.
//
// The loop never blocks on a socket write: every handler below either pushes to
// a buffered channel or hands off to a per-connection writer goroutine. One
// slow local server must not stall an entire tunnel.
func (s *Server) tunnelReadLoop(tunnel *Tunnel) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("panic in tunnelReadLoop", "panic", r, "tunnel_id", tunnel.ID)
		}
		s.tunnels.Unregister(tunnel.ID)
		tunnel.Conn.Close()
		s.logger.Info("tunnel disconnected",
			"tunnel_id", tunnel.ID,
			"subdomain", tunnel.Subdomain,
			"username", tunnel.Username,
		)
	}()

	// Set initial read deadline; pong handler resets it.
	tunnel.Conn.SetReadDeadline(time.Now().Add(s.pongWait))
	tunnel.Conn.SetPongHandler(func(string) error {
		tunnel.Conn.SetReadDeadline(time.Now().Add(s.pongWait))
		tunnel.mu.Lock()
		tunnel.lastActivity = time.Now()
		tunnel.mu.Unlock()
		return nil
	})

	for {
		msgType, msg, err := tunnel.Conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				s.logger.Info("tunnel closed normally", "tunnel_id", tunnel.ID)
			} else if !websocket.IsUnexpectedCloseError(err) {
				s.logger.Info("tunnel read deadline exceeded", "tunnel_id", tunnel.ID)
			} else {
				s.logger.Error("tunnel read error", "error", err, "tunnel_id", tunnel.ID)
			}
			return
		}

		// Update activity.
		tunnel.mu.Lock()
		tunnel.lastActivity = time.Now()
		tunnel.mu.Unlock()

		if msgType == websocket.BinaryMessage {
			if err := s.handleBinaryFrame(tunnel, msg); err != nil {
				s.logger.Error("fatal binary frame", "error", err, "tunnel_id", tunnel.ID)
				return
			}
			continue
		}

		env, err := protocol.ParseEnvelope(msg)
		if err != nil {
			s.logger.Error("invalid message from tunnel", "error", err, "tunnel_id", tunnel.ID)
			continue
		}

		switch env.Type {
		case protocol.TypeData:
			var frame protocol.DataFrame
			if err := env.ParsePayload(&frame); err != nil {
				s.logger.Error("invalid data frame", "error", err, "tunnel_id", tunnel.ID)
				continue
			}
			if len(frame.Data) > protocol.MaxDataFrameBytes {
				s.frameSizeViolation(tunnel, env.Type, len(frame.Data), protocol.MaxDataFrameBytes)
				return
			}
			s.handleStreamData(tunnel, frame.ConnID, frame.Data)

		case protocol.TypeRespHeader:
			var hdr protocol.RespHeaderFrame
			if err := env.ParsePayload(&hdr); err != nil {
				s.logger.Error("invalid resp_header frame", "error", err, "tunnel_id", tunnel.ID)
				continue
			}
			s.handleRespHeader(tunnel, &hdr)

		case protocol.TypeRespBody:
			var frame protocol.DataFrame
			if err := env.ParsePayload(&frame); err != nil {
				s.logger.Error("invalid resp_body frame", "error", err, "tunnel_id", tunnel.ID)
				continue
			}
			if len(frame.Data) > protocol.MaxStreamChunkBytes {
				s.frameSizeViolation(tunnel, env.Type, len(frame.Data), protocol.MaxStreamChunkBytes)
				return
			}
			s.handleRespBody(tunnel, frame.ConnID, frame.Data)

		case protocol.TypeRespEnd:
			var closeFrame protocol.CloseFrame
			if err := env.ParsePayload(&closeFrame); err != nil {
				s.logger.Error("invalid resp_end frame", "error", err, "tunnel_id", tunnel.ID)
				continue
			}
			s.handleRespEnd(tunnel, &closeFrame)

		case protocol.TypeTCPData:
			var frame protocol.DataFrame
			if err := env.ParsePayload(&frame); err != nil {
				s.logger.Error("invalid TCP data frame", "error", err, "tunnel_id", tunnel.ID)
				continue
			}
			if len(frame.Data) > protocol.MaxStreamChunkBytes {
				s.frameSizeViolation(tunnel, env.Type, len(frame.Data), protocol.MaxStreamChunkBytes)
				return
			}
			HandleTCPDataFromClient(tunnel, frame.ConnID, frame.Data, s.logger)

		case protocol.TypeClose:
			var closeFrame protocol.CloseFrame
			if err := env.ParsePayload(&closeFrame); err == nil {
				switch closeFrame.Reason {
				case "graceful":
					tunnel.graceful.Store(true)
					s.logger.Info("client signaled graceful close", "tunnel_id", tunnel.ID)
				case protocol.CloseReasonTCPEOF:
					s.closeTCPConn(tunnel, closeFrame.ConnID)
				}
			}

		case protocol.TypePong:
			// Application-level pong (WebSocket-level handled by PongHandler).

		default:
			s.logger.Warn("unknown message type from tunnel", "type", env.Type, "tunnel_id", tunnel.ID)
		}
	}
}

// handleBinaryFrame dispatches a binary data frame. A non-nil return is a
// protocol violation that must tear down the tunnel.
//
// The payload aliases the buffer gorilla allocated for this message. That
// buffer is not reused across reads, so handing it onward without a copy is
// safe and saves an allocation per chunk.
func (s *Server) handleBinaryFrame(tunnel *Tunnel, msg []byte) error {
	frameType, connID, payload, err := protocol.DecodeBinaryFrame(msg)
	if err != nil {
		s.logger.Error("invalid binary frame", "error", err, "tunnel_id", tunnel.ID)
		return nil
	}

	var limit int
	switch frameType {
	case protocol.BinTypeRespBody, protocol.BinTypeTCPData:
		limit = protocol.MaxStreamChunkBytes
	case protocol.BinTypeData:
		limit = protocol.MaxDataFrameBytes
	default:
		s.logger.Warn("unknown binary frame type", "type", frameType, "tunnel_id", tunnel.ID)
		return nil
	}
	if len(payload) > limit {
		return s.frameSizeViolation(tunnel, fmt.Sprintf("binary(%d)", frameType), len(payload), limit)
	}

	switch frameType {
	case protocol.BinTypeRespBody:
		s.handleRespBody(tunnel, connID, payload)
	case protocol.BinTypeData:
		s.handleStreamData(tunnel, connID, payload)
	case protocol.BinTypeTCPData:
		HandleTCPDataFromClient(tunnel, connID, payload, s.logger)
	}
	return nil
}

// frameSizeViolation logs a peer that sent an oversized frame and returns the
// error that ends the read loop. The per-connection queues behind these
// frames are sized for the documented chunk sizes; honoring a giant frame
// lets one frame pin megabytes per queue slot, so the tunnel comes down.
func (s *Server) frameSizeViolation(tunnel *Tunnel, frameType string, size, limit int) error {
	err := fmt.Errorf("%s frame payload %d bytes exceeds protocol limit %d", frameType, size, limit)
	s.logger.Error("protocol violation from tunnel peer — disconnecting",
		"tunnel_id", tunnel.ID,
		"username", tunnel.Username,
		"frame_type", frameType,
		"payload_bytes", size,
		"limit", limit,
	)
	return err
}

// handleStreamData routes bytes from the tunnel client for a logical
// connection. Post-streaming refactor this carries WebSocket passthrough only;
// HTTP responses use the resp_* frames handled below. Old clients may still
// send a whole buffered HTTP response here, which the legacy branch accepts.
func (s *Server) handleStreamData(tunnel *Tunnel, connID string, data []byte) {
	val, ok := tunnel.pending.Load(connID)
	if !ok {
		// Stale frame after the conn was torn down — common on cancel, not an error.
		return
	}

	switch conn := val.(type) {
	case *StreamingConn:
		if !conn.TrySend(data) {
			s.logger.Warn("streaming connection closed: consumer fell behind or connection ended",
				"conn_id", connID,
				"tunnel_id", tunnel.ID,
			)
		}
	case *ProxiedConn:
		// Legacy path: old clients may still send TypeData for HTTP responses.
		// Treat the whole blob as a single body chunk wrapped in header+body+end
		// so we stay compatible with pre-streaming tunnel clients.
		s.logger.Warn("received legacy data frame for HTTP response; tunnel client is out of date",
			"conn_id", connID,
			"tunnel_id", tunnel.ID,
		)
		conn.PushHeader(&protocol.RespHeaderFrame{
			ConnID:     connID,
			TunnelID:   tunnel.ID,
			StatusCode: 0, // signals "raw bytes, parse them"
		})
		conn.PushBody(data)
		conn.PushEnd("")
	default:
		s.logger.Warn("unknown pending connection type", "conn_id", connID)
	}
}

// handleRespHeader delivers streaming response headers to the waiting ProxiedConn.
func (s *Server) handleRespHeader(tunnel *Tunnel, hdr *protocol.RespHeaderFrame) {
	val, ok := tunnel.pending.Load(hdr.ConnID)
	if !ok {
		return
	}
	conn, ok := val.(*ProxiedConn)
	if !ok {
		s.logger.Warn("resp_header for non-HTTP conn", "conn_id", hdr.ConnID)
		return
	}
	if !conn.PushHeader(hdr) {
		s.logger.Warn("dropped resp_header (slow consumer)", "conn_id", hdr.ConnID)
	}
}

// handleRespBody delivers a streaming response body chunk.
func (s *Server) handleRespBody(tunnel *Tunnel, connID string, data []byte) {
	val, ok := tunnel.pending.Load(connID)
	if !ok {
		return
	}
	conn, ok := val.(*ProxiedConn)
	if !ok {
		return
	}
	if !conn.PushBody(data) {
		s.logger.Warn("response aborted: consumer fell behind", "conn_id", connID, "tunnel_id", tunnel.ID)
	}
}

// handleRespEnd signals end-of-stream for a proxied HTTP response.
func (s *Server) handleRespEnd(tunnel *Tunnel, cf *protocol.CloseFrame) {
	val, ok := tunnel.pending.Load(cf.ConnID)
	if !ok {
		return
	}
	conn, ok := val.(*ProxiedConn)
	if !ok {
		return
	}
	conn.PushEnd(cf.Reason)
}

// closeTCPConn tears down a logical connection the client reports as finished
// (close reason tcp_eof): a TCP-tunnel socket or a WebSocket passthrough
// stream, whose public side is closed so the browser sees a clean end rather
// than waiting on a dead local server.
func (s *Server) closeTCPConn(tunnel *Tunnel, connID string) {
	if val, ok := tunnel.tcpConns.LoadAndDelete(connID); ok {
		if w, ok := val.(*connWriter); ok {
			w.Close()
		}
		return
	}
	if val, ok := tunnel.pending.Load(connID); ok {
		if sc, ok := val.(*StreamingConn); ok {
			sc.Close()
		}
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok"}`)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	usersLoaded := s.users.Count()
	if usersLoaded == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `{"status":"not_ready","reason":"no_users_loaded"}`)
		return
	}

	fmt.Fprintf(w, `{"status":"ready","active_tunnels":%d,"users_loaded":%d}`,
		s.tunnels.ActiveCount(),
		usersLoaded,
	)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"service":"mabo-tunnel","version":%q,"domain":%q,"active_tunnels":%d}`,
		version.Version,
		s.config.Domain,
		s.tunnels.ActiveCount(),
	)
}
