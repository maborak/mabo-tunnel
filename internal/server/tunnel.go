package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maborak/mabo-tunnel/internal/protocol"
	"github.com/gorilla/websocket"
)

// Plan limits for tunnel quotas.
var PlanLimits = map[string]int{
	"free": 1,
	"pro":  10,
}

// tunnelWriteTimeout bounds a single WebSocket write to the tunnel client.
const tunnelWriteTimeout = 10 * time.Second

// Tunnel represents an active tunnel connection.
type Tunnel struct {
	ID          string
	Subdomain   string
	Username    string
	Plan        string
	SessionID   string // client-generated, persists across reconnects
	Protocol    string // "http" (default) or "tcp"
	TCPPort     int    // assigned TCP listen port (only for TCP tunnels)
	ConnectedAt time.Time
	AllowedIPs  []string // IP allow list (empty = allow all)
	DeniedIPs   []string // IP deny list (checked first)
	BasicAuth   string   // "user:pass" for HTTP Basic Auth (empty = no auth)
	Binary      bool     // client negotiated binary data frames
	Conn        *websocket.Conn

	// tcpListener is the TCP listener for TCP tunnels (nil for HTTP).
	tcpListener net.Listener

	// pending tracks in-flight proxied connections awaiting responses.
	pending sync.Map // connID → *ProxiedConn | *StreamingConn

	// pendingCount is the number of in-flight proxied HTTP connections, used
	// to enforce maxProxiedPerTunnel without walking the map.
	pendingCount atomic.Int64

	// tcpConns tracks active TCP connections for bidirectional streaming.
	tcpConns sync.Map // connID → *connWriter

	// writeMu serializes writes to the WebSocket connection.
	writeMu sync.Mutex

	// done is closed when the tunnel is torn down.
	done     chan struct{}
	doneOnce sync.Once

	// graceful is set when the client sent a clean close (Ctrl+C). Written
	// by the read loop, read by Unregister from other goroutines.
	graceful atomic.Bool

	// lastActivity tracks last message received for stale detection.
	mu           sync.Mutex
	lastActivity time.Time
}

// writeMessage sends a single WebSocket message under the write lock.
func (t *Tunnel) writeMessage(msgType int, data []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.Conn.SetWriteDeadline(time.Now().Add(tunnelWriteTimeout))
	err := t.Conn.WriteMessage(msgType, data)
	t.Conn.SetWriteDeadline(time.Time{})
	return err
}

// WriteEnvelope sends a JSON control message to the tunnel client.
func (t *Tunnel) WriteEnvelope(env *protocol.Envelope) error {
	msgBytes, err := env.Marshal()
	if err != nil {
		return err
	}
	return t.writeMessage(websocket.TextMessage, msgBytes)
}

// WriteControl builds and sends a JSON control message in one step.
func (t *Tunnel) WriteControl(msgType string, payload any) error {
	env, err := protocol.NewEnvelope(msgType, payload)
	if err != nil {
		return err
	}
	return t.WriteEnvelope(env)
}

// WriteData sends bulk bytes for a logical connection. Clients that negotiated
// binary framing get a binary frame; older clients get the equivalent JSON
// frame, where the payload costs an extra 33% as base64.
func (t *Tunnel) WriteData(binType byte, jsonType, connID string, payload []byte) error {
	if t.Binary {
		buf, err := protocol.EncodeBinaryFrame(binType, connID, payload)
		if err != nil {
			return err
		}
		return t.writeMessage(websocket.BinaryMessage, buf)
	}
	return t.WriteControl(jsonType, &protocol.DataFrame{
		ConnID:   connID,
		TunnelID: t.ID,
		Data:     payload,
	})
}

// ── connWriter ──────────────────────────────────────────────────────────────

// connWriterQueue bounds how far a slow socket may fall behind before the
// connection is torn down.
const connWriterQueue = 256

// connWriter serializes writes to a net.Conn through a single goroutine. It
// exists for two reasons: the tunnel's shared read loop must never block on one
// slow socket, and a byte stream must not be reordered by concurrent writers.
type connWriter struct {
	conn      net.Conn
	ch        chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

func newConnWriter(c net.Conn) *connWriter {
	w := &connWriter{
		conn: c,
		ch:   make(chan []byte, connWriterQueue),
		done: make(chan struct{}),
	}
	go w.run()
	return w
}

func (w *connWriter) run() {
	defer w.conn.Close()
	for {
		select {
		case b := <-w.ch:
			w.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			_, err := w.conn.Write(b)
			w.conn.SetWriteDeadline(time.Time{})
			if err != nil {
				return
			}
		case <-w.done:
			return
		}
	}
}

// Send queues bytes for writing without blocking the caller. It returns false
// if the connection is closed or the queue is full. Dropping bytes from the
// middle of a stream would corrupt it silently, so a full queue closes the
// connection instead — the peer sees a broken transfer, which is true.
func (w *connWriter) Send(b []byte) bool {
	select {
	case <-w.done:
		return false
	default:
	}
	select {
	case w.ch <- b:
		return true
	default:
		w.Close()
		return false
	}
}

// Conn returns the underlying connection.
func (w *connWriter) Conn() net.Conn { return w.conn }

// Close tears down the writer and its connection.
func (w *connWriter) Close() {
	w.closeOnce.Do(func() {
		close(w.done)
		w.conn.Close()
	})
}

// ── ProxiedConn ─────────────────────────────────────────────────────────────

// ProxyEventKind identifies the type of a streaming response event.
type ProxyEventKind int

const (
	ProxyEventHeader ProxyEventKind = iota
	ProxyEventBody
	ProxyEventEnd
)

// ProxyEvent is a single event in the response stream for an in-flight
// HTTP request proxied through the tunnel. Events arrive in order: exactly
// one Header, zero or more Body, exactly one End.
type ProxyEvent struct {
	Kind   ProxyEventKind
	Header *protocol.RespHeaderFrame
	Body   []byte
	// EndReason is set on ProxyEventEnd. Empty means a clean EOF; a non-empty
	// value describes an error from the tunnel client.
	EndReason string
}

// ProxiedConn represents a single in-flight HTTP request proxied through the
// tunnel. The server writes the request bytes via Request, then drains Events
// to stream the response back to the public caller as it arrives.
type ProxiedConn struct {
	ID      string
	Request []byte
	// Events carries an ordered stream of response events from the tunnel
	// client. Buffered so the tunnel WS readLoop never blocks on a single
	// slow public consumer.
	Events chan ProxyEvent
	mu     sync.Mutex
	closed bool
	// buffered counts body bytes sitting in Events awaiting the consumer.
	// The channel depth bounds event COUNT; this bounds event SIZE, so a
	// peer sending oversized chunks cannot park megabytes per queue slot.
	buffered int
	// overflowed records that events were discarded because the buffer filled.
	// The public response is then incomplete and must be aborted rather than
	// terminated cleanly — see streamResponse.
	overflowed bool
}

// proxiedConnBuffer is how many response events may queue for one request
// before the public consumer is considered hopelessly behind.
const proxiedConnBuffer = 512

// maxProxiedBufferedBytes bounds the body bytes one request may park in the
// event buffer: the channel depth times the designed 16 KiB response chunk.
// Frame-level limits stop a single oversized chunk; this stops many
// legitimate-sized ones.
const maxProxiedBufferedBytes = proxiedConnBuffer * 16 * 1024

// NewProxiedConn creates a ProxiedConn with an adequately-buffered event channel.
func NewProxiedConn(id string, request []byte) *ProxiedConn {
	return &ProxiedConn{
		ID:      id,
		Request: request,
		Events:  make(chan ProxyEvent, proxiedConnBuffer),
	}
}

// pushEvent attempts to enqueue an event non-blockingly. If the buffer is full
// (slow public consumer, or more body bytes parked than the byte bound
// allows) or the connection has been closed, the event is dropped and the
// connection is marked closed so the reader bails out.
//
// A dropped body chunk means the response the public caller receives is not
// the response the backend produced, so overflow is recorded and the reader
// aborts the HTTP response rather than ending it normally.
func (pc *ProxiedConn) pushEvent(ev ProxyEvent) bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.closed {
		return false
	}
	if ev.Kind == ProxyEventBody && pc.buffered+len(ev.Body) > maxProxiedBufferedBytes {
		pc.overflowed = true
		pc.closed = true
		close(pc.Events)
		return false
	}
	select {
	case pc.Events <- ev:
		if ev.Kind == ProxyEventBody {
			pc.buffered += len(ev.Body)
		}
		return true
	default:
		pc.overflowed = true
		pc.closed = true
		close(pc.Events)
		return false
	}
}

// release returns byte budget to the buffer after the consumer has taken an
// event off the channel. Only the single consumer goroutine calls this.
func (pc *ProxiedConn) release(n int) {
	pc.mu.Lock()
	pc.buffered -= n
	pc.mu.Unlock()
}

// PushHeader enqueues a response header event. Returns false if the connection
// is closed or the buffer is full.
func (pc *ProxiedConn) PushHeader(h *protocol.RespHeaderFrame) bool {
	return pc.pushEvent(ProxyEvent{Kind: ProxyEventHeader, Header: h})
}

// PushBody enqueues a response body chunk event.
func (pc *ProxiedConn) PushBody(data []byte) bool {
	return pc.pushEvent(ProxyEvent{Kind: ProxyEventBody, Body: data})
}

// PushEnd enqueues the terminal response event with an optional error reason.
func (pc *ProxiedConn) PushEnd(reason string) bool {
	return pc.pushEvent(ProxyEvent{Kind: ProxyEventEnd, EndReason: reason})
}

// Overflowed reports whether response events were discarded, meaning the body
// delivered to the public caller is incomplete.
func (pc *ProxiedConn) Overflowed() bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.overflowed
}

// Close marks the proxied connection as closed and drains the events channel.
func (pc *ProxiedConn) Close() {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.closed {
		return
	}
	pc.closed = true
	close(pc.Events)
}

// ── StreamingConn ───────────────────────────────────────────────────────────

// StreamingConn represents a long-lived bidirectional connection through the
// tunnel, used for WebSocket passthrough. Unlike ProxiedConn which expects a
// single response, StreamingConn supports continuous data flow in both directions.
type StreamingConn struct {
	ID      string
	DataCh  chan []byte   // receives data frames from the tunnel client
	CloseCh chan struct{} // signals connection close
	mu      sync.Mutex
	closed  bool
	// buffered counts bytes sitting in DataCh awaiting the consumer, bounding
	// memory per passthrough connection independently of chunk sizes.
	buffered int
}

// streamingConnBuffer is the DataCh depth.
const streamingConnBuffer = 256

// maxStreamBufferedBytes bounds the bytes one passthrough connection may park
// in DataCh: the channel depth times the 32 KiB chunks the peers send.
const maxStreamBufferedBytes = streamingConnBuffer * 32 * 1024

// TrySend attempts to send data to the streaming connection. A full buffer
// (by count or by bytes) closes the connection rather than dropping the
// chunk: this is a raw byte stream, and a hole in it desynchronizes WebSocket
// framing at the far end.
func (sc *StreamingConn) TrySend(data []byte) bool {
	sc.mu.Lock()
	if sc.closed {
		sc.mu.Unlock()
		return false
	}
	if sc.buffered+len(data) > maxStreamBufferedBytes {
		sc.closed = true
		close(sc.CloseCh)
		sc.mu.Unlock()
		return false
	}
	select {
	case sc.DataCh <- data:
		sc.buffered += len(data)
		sc.mu.Unlock()
		return true
	default:
		sc.closed = true
		close(sc.CloseCh)
		sc.mu.Unlock()
		return false
	}
}

// release returns byte budget to the buffer after the consumer has taken a
// chunk off the channel. Only the single consumer goroutine calls this.
func (sc *StreamingConn) release(n int) {
	sc.mu.Lock()
	sc.buffered -= n
	sc.mu.Unlock()
}

// Close marks the streaming connection as closed and signals via CloseCh.
func (sc *StreamingConn) Close() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.closed {
		return
	}
	sc.closed = true
	close(sc.CloseCh)
}

// ── TunnelManager ───────────────────────────────────────────────────────────

// reservation holds a subdomain reserved for a user after disconnect.
type reservation struct {
	subdomain string
	// username is the owner. A reservation is only honored for the user who
	// held the subdomain — session IDs alone must not transfer ownership.
	username  string
	expiresAt time.Time
}

// TunnelManager handles tunnel registration, lookup, and cleanup.
type TunnelManager struct {
	mu       sync.RWMutex
	tunnels  map[string]*Tunnel      // keyed by tunnel ID
	byHost   map[string]*Tunnel      // keyed by subdomain
	byUser   map[string]int          // username → active tunnel count
	reserved map[string]*reservation // session_id → reserved subdomain (survives reconnect)
	domain   string
	logger   *slog.Logger
	stopCh   chan struct{}
	stopOnce sync.Once

	// TCP port allocation
	tcpPortMin int            // start of TCP port range (inclusive)
	tcpPortMax int            // end of TCP port range (inclusive)
	tcpUsed    map[int]string // port → tunnel ID
}

// NewTunnelManager creates a new TunnelManager with stale cleanup.
func NewTunnelManager(domain string, tcpPortMin, tcpPortMax int, logger *slog.Logger) *TunnelManager {
	tm := &TunnelManager{
		tunnels:    make(map[string]*Tunnel),
		byHost:     make(map[string]*Tunnel),
		byUser:     make(map[string]int),
		reserved:   make(map[string]*reservation),
		domain:     domain,
		logger:     logger,
		stopCh:     make(chan struct{}),
		tcpPortMin: tcpPortMin,
		tcpPortMax: tcpPortMax,
		tcpUsed:    make(map[int]string),
	}
	go tm.cleanupLoop()
	return tm
}

// Stop stops the cleanup loop.
func (m *TunnelManager) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh) })
}

// cleanupLoop periodically removes stale tunnels.
func (m *TunnelManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.cleanupStale()
		case <-m.stopCh:
			return
		}
	}
}

func (m *TunnelManager) cleanupStale() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	staleThreshold := 5 * time.Minute

	for tunnelID, tunnel := range m.tunnels {
		tunnel.mu.Lock()
		lastActivity := tunnel.lastActivity
		tunnel.mu.Unlock()

		if now.Sub(lastActivity) > staleThreshold {
			m.logger.Warn("removing stale tunnel",
				"tunnel_id", tunnelID,
				"subdomain", tunnel.Subdomain,
				"username", tunnel.Username,
				"idle", now.Sub(lastActivity),
			)
			// Reserve the subdomain for the session before removing.
			if tunnel.SessionID != "" {
				m.reserved[tunnel.SessionID] = &reservation{
					subdomain: tunnel.Subdomain,
					username:  tunnel.Username,
					expiresAt: now.Add(5 * time.Minute),
				}
			}
			m.teardownLocked(tunnel)
			delete(m.tunnels, tunnelID)
			delete(m.byHost, tunnel.Subdomain)
			m.byUser[tunnel.Username]--
		}
	}

	// Expire old reservations.
	for sessionID, res := range m.reserved {
		if now.After(res.expiresAt) {
			m.logger.Info("reservation expired", "session_id", sessionID, "subdomain", res.subdomain)
			delete(m.reserved, sessionID)
		}
	}
}

// teardownLocked releases a tunnel's resources. Must be called with m.mu held.
func (m *TunnelManager) teardownLocked(tunnel *Tunnel) {
	if tunnel.tcpListener != nil {
		tunnel.tcpListener.Close()
	}
	tunnel.tcpConns.Range(func(key, value any) bool {
		if w, ok := value.(*connWriter); ok {
			w.Close()
		}
		return true
	})
	if tunnel.TCPPort != 0 {
		delete(m.tcpUsed, tunnel.TCPPort)
	}
	tunnel.doneOnce.Do(func() { close(tunnel.done) })
	tunnel.Conn.Close()
}

// RegisterOpts holds parameters for tunnel registration.
type RegisterOpts struct {
	Conn       *websocket.Conn
	Username   string
	Plan       string
	Subdomain  string // explicit subdomain request
	SessionID  string // client session ID for reconnect
	Name       string // named tunnel (e.g. "ui" → username_ui)
	AllowedIPs []string
	DeniedIPs  []string
	BasicAuth  string // "user:pass" for HTTP Basic Auth
	Binary     bool   // client negotiated binary data frames
}

// Register adds a new tunnel and assigns a subdomain.
func (m *TunnelManager) Register(opts RegisterOpts) (*Tunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Enforce plan quotas.
	maxTunnels := PlanLimits[opts.Plan]
	if maxTunnels == 0 {
		maxTunnels = 1
	}
	if m.byUser[opts.Username] >= maxTunnels {
		return nil, fmt.Errorf("quota exceeded: %d/%d tunnels for plan %q", m.byUser[opts.Username], maxTunnels, opts.Plan)
	}

	subdomain := opts.Subdomain

	// Named tunnel: username_name (e.g. wilmer_ui)
	if subdomain == "" && opts.Name != "" {
		subdomain = opts.Username + "-" + opts.Name
	}

	// Session-based reconnect: reuse the subdomain from a previous session.
	if subdomain == "" && opts.SessionID != "" {
		if res, ok := m.reserved[opts.SessionID]; ok {
			// A reservation belongs to the user who earned it. Anything else
			// would let one tenant reclaim another's subdomain by presenting
			// a session ID.
			if res.username == opts.Username {
				if _, taken := m.byHost[res.subdomain]; !taken {
					subdomain = res.subdomain
					m.logger.Info("reusing reserved subdomain",
						"session_id", opts.SessionID,
						"username", opts.Username,
						"subdomain", subdomain,
					)
				}
				delete(m.reserved, opts.SessionID)
			}
		}
	}

	// Generate random subdomain if nothing else matched.
	if subdomain == "" {
		var err error
		subdomain, err = generateSubdomain()
		if err != nil {
			return nil, err
		}
	}

	if len(subdomain) > 63 {
		return nil, fmt.Errorf("subdomain too long: %d chars (max 63)", len(subdomain))
	}

	if err := m.checkSubdomainClaim(subdomain, opts); err != nil {
		return nil, err
	}

	tunnelID, err := generateTunnelID()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tunnel := &Tunnel{
		ID:           tunnelID,
		Subdomain:    subdomain,
		Username:     opts.Username,
		Plan:         opts.Plan,
		SessionID:    opts.SessionID,
		ConnectedAt:  now,
		AllowedIPs:   opts.AllowedIPs,
		DeniedIPs:    opts.DeniedIPs,
		BasicAuth:    opts.BasicAuth,
		Binary:       opts.Binary,
		Conn:         opts.Conn,
		done:         make(chan struct{}),
		lastActivity: now,
	}

	m.tunnels[tunnelID] = tunnel
	m.byHost[subdomain] = tunnel
	m.byUser[opts.Username]++

	return tunnel, nil
}

// checkSubdomainClaim enforces that a subdomain about to be assigned belongs
// — or may belong — to the requesting user. Must be called with m.mu held.
//
// Two cases, both about tenant isolation:
//
//  1. An existing live tunnel holds it. Only the same user reconnecting with
//     the same session ID may evict; session IDs transfer nothing between
//     users, so matching on SessionID alone would let a tenant presenting a
//     victim's session ID tear down the victim's live tunnel and take the URL.
//  2. Nobody holds it, but a reconnect reservation does. Public clients stay
//     pointed at the URL through brief outages, so handing it to a different
//     user mid-window would redirect a victim's traffic into the attacker's
//     tunnel. The owner may reclaim it (new process, new session ID); anyone
//     else waits for the reservation to expire.
func (m *TunnelManager) checkSubdomainClaim(subdomain string, opts RegisterOpts) error {
	if existing, taken := m.byHost[subdomain]; taken {
		if opts.SessionID != "" && existing.SessionID == opts.SessionID && existing.Username == opts.Username {
			// Same user's session reconnecting — evict the old (dead) tunnel.
			m.logger.Info("evicting stale tunnel for session reconnect",
				"old_tunnel_id", existing.ID,
				"session_id", opts.SessionID,
				"subdomain", subdomain,
			)
			existing.doneOnce.Do(func() { close(existing.done) })
			existing.Conn.Close()
			delete(m.tunnels, existing.ID)
			delete(m.byHost, subdomain)
			m.byUser[existing.Username]--
			return nil
		}
		return fmt.Errorf("subdomain %q is already in use", subdomain)
	}

	if res := m.reservationForSubdomain(subdomain); res != nil && res.username != opts.Username {
		return fmt.Errorf("subdomain %q is reserved for a recent session of another user; it is released at most 5 minutes after they disconnect", subdomain)
	}
	return nil
}

// reservationForSubdomain returns the unexpired reservation holding a
// subdomain, if any, purging expired entries as it walks. Must be called
// with m.mu held.
func (m *TunnelManager) reservationForSubdomain(subdomain string) *reservation {
	now := time.Now()
	var found *reservation
	for sid, res := range m.reserved {
		if now.After(res.expiresAt) {
			delete(m.reserved, sid)
			continue
		}
		if res.subdomain == subdomain && found == nil {
			found = res
		}
	}
	return found
}

// Unregister removes a tunnel. If the disconnect was not graceful (network glitch),
// reserves the subdomain so the same session can reclaim it on reconnect.
func (m *TunnelManager) Unregister(tunnelID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tunnel, ok := m.tunnels[tunnelID]
	if !ok {
		return
	}

	// Only reserve if NOT a graceful close (Ctrl+C) and session ID exists.
	if !tunnel.graceful.Load() && tunnel.SessionID != "" {
		m.reserved[tunnel.SessionID] = &reservation{
			subdomain: tunnel.Subdomain,
			username:  tunnel.Username,
			expiresAt: time.Now().Add(5 * time.Minute),
		}
		m.logger.Info("subdomain reserved for reconnect",
			"session_id", tunnel.SessionID,
			"username", tunnel.Username,
			"subdomain", tunnel.Subdomain,
			"expires_in", "5m",
		)
	} else {
		m.logger.Info("subdomain released (graceful close)",
			"username", tunnel.Username,
			"subdomain", tunnel.Subdomain,
		)
	}

	m.teardownLocked(tunnel)
	delete(m.tunnels, tunnelID)
	delete(m.byHost, tunnel.Subdomain)
	m.byUser[tunnel.Username]--
}

// LookupByHost finds a tunnel by its subdomain.
func (m *TunnelManager) LookupByHost(subdomain string) (*Tunnel, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tunnel, ok := m.byHost[subdomain]
	return tunnel, ok
}

// LookupByID finds a tunnel by its ID.
func (m *TunnelManager) LookupByID(tunnelID string) *Tunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tunnels[tunnelID]
}

// List returns all active tunnels.
func (m *TunnelManager) List() []*Tunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*Tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		result = append(result, t)
	}
	return result
}

// ActiveCount returns the number of active tunnels.
func (m *TunnelManager) ActiveCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tunnels)
}

// URL returns the full tunnel URL for a subdomain.
func (m *TunnelManager) URL(subdomain, scheme string) string {
	if scheme == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s.%s", scheme, subdomain, m.domain)
}

// DrainAll closes all tunnels gracefully.
func (m *TunnelManager) DrainAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for tunnelID, tunnel := range m.tunnels {
		tunnel.writeMu.Lock()
		tunnel.Conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseGoingAway, "server shutting down"))
		tunnel.writeMu.Unlock()

		m.teardownLocked(tunnel)
		delete(m.tunnels, tunnelID)
		delete(m.byHost, tunnel.Subdomain)
	}
}

// RegisterTCP registers a TCP tunnel and allocates a port from the configured range.
// The caller must start the TCP listener (via TCPProxy) after registration.
func (m *TunnelManager) RegisterTCP(opts RegisterOpts) (*Tunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Enforce plan quotas.
	maxTunnels := PlanLimits[opts.Plan]
	if maxTunnels == 0 {
		maxTunnels = 1
	}
	if m.byUser[opts.Username] >= maxTunnels {
		return nil, fmt.Errorf("quota exceeded: %d/%d tunnels for plan %q", m.byUser[opts.Username], maxTunnels, opts.Plan)
	}

	// Allocate a TCP port.
	port, err := m.allocateTCPPort()
	if err != nil {
		return nil, err
	}

	// Start listening on the allocated port.
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		delete(m.tcpUsed, port)
		return nil, fmt.Errorf("listen on TCP port %d: %w", port, err)
	}

	subdomain := opts.Subdomain
	if subdomain == "" && opts.Name != "" {
		subdomain = opts.Username + "-" + opts.Name
	}
	if subdomain == "" && opts.SessionID != "" {
		if res, ok := m.reserved[opts.SessionID]; ok {
			if res.username == opts.Username {
				if _, taken := m.byHost[res.subdomain]; !taken {
					subdomain = res.subdomain
				}
				delete(m.reserved, opts.SessionID)
			}
		}
	}
	if subdomain == "" {
		subdomain, err = generateSubdomain()
		if err != nil {
			listener.Close()
			delete(m.tcpUsed, port)
			return nil, err
		}
	}

	if err := m.checkSubdomainClaim(subdomain, opts); err != nil {
		listener.Close()
		delete(m.tcpUsed, port)
		return nil, err
	}

	tunnelID, err := generateTunnelID()
	if err != nil {
		listener.Close()
		delete(m.tcpUsed, port)
		return nil, err
	}

	now := time.Now()
	tunnel := &Tunnel{
		ID:           tunnelID,
		Subdomain:    subdomain,
		Username:     opts.Username,
		Plan:         opts.Plan,
		SessionID:    opts.SessionID,
		Protocol:     protocol.ProtocolTCP,
		TCPPort:      port,
		ConnectedAt:  now,
		AllowedIPs:   opts.AllowedIPs,
		DeniedIPs:    opts.DeniedIPs,
		BasicAuth:    opts.BasicAuth,
		Binary:       opts.Binary,
		Conn:         opts.Conn,
		tcpListener:  listener,
		done:         make(chan struct{}),
		lastActivity: now,
	}

	m.tunnels[tunnelID] = tunnel
	m.byHost[subdomain] = tunnel
	m.byUser[opts.Username]++

	return tunnel, nil
}

// allocateTCPPort finds an unused port in the configured range.
// Must be called with m.mu held.
func (m *TunnelManager) allocateTCPPort() (int, error) {
	for port := m.tcpPortMin; port <= m.tcpPortMax; port++ {
		if _, used := m.tcpUsed[port]; !used {
			m.tcpUsed[port] = "" // placeholder, caller sets tunnel ID
			return port, nil
		}
	}
	return 0, fmt.Errorf("no TCP ports available in range %d-%d", m.tcpPortMin, m.tcpPortMax)
}

func generateTunnelID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate tunnel ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func generateSubdomain() (string, error) {
	b := make([]byte, 8) // 64-bit: much harder to enumerate than 32-bit
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate subdomain: %w", err)
	}
	return hex.EncodeToString(b), nil
}
