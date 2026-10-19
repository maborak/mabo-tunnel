package server

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/maborak/mabo-tunnel/internal/protocol"
)

// Max request body size (10 MB).
const maxRequestBodySize = 10 * 1024 * 1024

// reqChunkSize is how much request body is forwarded per frame.
const reqChunkSize = 32 * 1024

// defaultTrustedProxies are the ranges an X-Forwarded-For header is honored
// from when none are configured: loopback only, the reverse proxy on the same
// host. A proxy on a container network or another private host must be named
// explicitly with --trusted-proxies. Trusting the private ranges by default
// let every host that could reach the server — any neighbour on the LAN or
// the container network — describe its own origin, choosing its own
// rate-limit bucket and bypassing IP allow lists.
var defaultTrustedProxies = []string{
	"127.0.0.0/8", "::1/128",
}

// defaultFirstEventTimeout bounds how long a proxied request waits for the
// local server's response headers.
const defaultFirstEventTimeout = 60 * time.Second

// ProxyHandler handles incoming HTTP requests and routes them through tunnels.
type ProxyHandler struct {
	tunnels           *TunnelManager
	domain            string
	logger            *slog.Logger
	trustedProxies    []*net.IPNet
	firstEventTimeout time.Duration
	metrics           *Metrics
}

// SetMetrics attaches an optional metrics sink; nil (the default) disables
// metric collection on this handler.
func (p *ProxyHandler) SetMetrics(m *Metrics) {
	p.metrics = m
}

// NewProxyHandler creates a new ProxyHandler. trustedProxies is a list of
// CIDRs whose X-Forwarded-For headers are believed; empty means the defaults
// (loopback only).
func NewProxyHandler(tunnels *TunnelManager, domain string, trustedProxies []string, firstEventTimeout time.Duration, logger *slog.Logger) *ProxyHandler {
	if firstEventTimeout <= 0 {
		firstEventTimeout = defaultFirstEventTimeout
	}
	if len(trustedProxies) == 0 {
		trustedProxies = defaultTrustedProxies
	}
	nets := make([]*net.IPNet, 0, len(trustedProxies))
	for _, cidr := range trustedProxies {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			logger.Warn("ignoring invalid trusted proxy CIDR", "cidr", cidr, "error", err)
			continue
		}
		nets = append(nets, n)
	}
	return &ProxyHandler{
		tunnels:           tunnels,
		domain:            strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), ".")),
		logger:            logger,
		trustedProxies:    nets,
		firstEventTimeout: firstEventTimeout,
	}
}

// isWebSocketUpgrade returns true if the request is a WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// ServeHTTP routes incoming requests to the appropriate tunnel.
func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.metrics.Inc("mabo_http_requests_total", "")
	host := normalizeHost(r.Host)

	// Resolve the target tunnel from the host once: a
	// <subdomain>.<base-domain> host names its tunnel directly, anything else
	// must be a registered custom hostname. Resolving twice — custom lookup
	// first, then a byHost lookup of whatever subdomain the custom tunnel
	// happened to carry — let a custom-domain request be rerouted to whichever
	// other user held that subdomain.
	var tunnel *Tunnel
	if sub := p.extractSubdomain(host); sub != "" {
		var ok bool
		if tunnel, ok = p.tunnels.LookupByHost(sub); !ok {
			http.Error(w, fmt.Sprintf("Tunnel %q not found. It may have been closed.", sub), http.StatusNotFound)
			return
		}
	} else if t, ok := p.tunnels.LookupCustom(host); ok {
		tunnel = t
	} else {
		http.Error(w, "No tunnel specified. Use <subdomain>."+p.domain, http.StatusBadRequest)
		return
	}

	// IP filtering: check the requester's IP against the tunnel's deny/allow lists.
	if !p.checkIPAccess(r, tunnel) {
		http.Error(w, "Forbidden: your IP is not allowed to access this tunnel", http.StatusForbidden)
		return
	}

	// HTTP Basic Auth: challenge if the tunnel requires it.
	if tunnel.BasicAuth != "" {
		if !p.checkBasicAuth(r, tunnel.BasicAuth) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Tunnel"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// The edge consumed this credential; forwarding it would hand the
		// tunneled app a credential meant for the edge (F-17).
		r.Header.Del("Authorization")
	}

	// Per-tunnel request-rate cap. The bucket belongs to the tunnel, so the
	// limit travels with the tunnel across reconnects and is shared by every
	// concurrent public caller hammering it.
	if tunnel.rateLimiter != nil && !tunnel.rateLimiter.allow() {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// Bound how many requests one tunnel may have in flight, so a single
	// tunnel cannot pin unbounded memory in per-request event buffers. This
	// deliberately covers WebSocket passthrough too: a passthrough connection
	// is a request that never completes until the socket closes, so leaving
	// it outside the cap would make the cap decorative.
	if n := tunnel.pendingCount.Add(1); n > maxProxiedPerTunnel {
		tunnel.pendingCount.Add(-1)
		p.logger.Warn("tunnel at in-flight request limit",
			"tunnel_id", tunnel.ID,
			"limit", maxProxiedPerTunnel,
		)
		http.Error(w, "Tunnel is at its concurrent request limit", http.StatusServiceUnavailable)
		return
	}
	defer tunnel.pendingCount.Add(-1)

	// WebSocket upgrade requests get special bidirectional handling. The check
	// runs before hop-by-hop stripping so the upgrade tokens survive it.
	isUpgrade := isWebSocketUpgrade(r)

	// Headers that describe the caller's connection rather than the request
	// must not cross the tunnel hop, and the app behind the tunnel needs the
	// origin information this edge verified instead of the caller's word for
	// it.
	stripHopByHopRequest(r, isUpgrade)
	p.setForwardedFor(r)
	p.setForwardedProto(r)

	if isUpgrade {
		p.handleWebSocketProxy(w, r, tunnel)
		return
	}

	// Reject oversize uploads up front when Content-Length is known, so we
	// can return a clean 413 and push a notice to the tunnel owner.
	if r.ContentLength > maxRequestBodySize {
		p.notifyBodyTooLarge(tunnel, r, r.ContentLength)
		w.Header().Set("Connection", "close")
		http.Error(w, fmt.Sprintf("Request body exceeds %d bytes (tunnel limit)", maxRequestBodySize), http.StatusRequestEntityTooLarge)
		return
	}

	// Limit request body size. For chunked/unknown-length bodies, MaxBytesReader
	// enforces the cap while we read.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	p.logger.Debug("proxying request",
		"subdomain", tunnel.Subdomain,
		"method", r.Method,
		"path", r.URL.Path,
		"tunnel_id", tunnel.ID,
	)

	// Forward the request head only. The body streams behind it as its own
	// frames, so a large upload starts reaching the local server immediately
	// instead of being buffered whole at the edge first. The forwarded origin
	// headers were stamped above; the head now carries them into the tunnel.
	rawHead, err := httputil.DumpRequest(r, false)
	if err != nil {
		p.logger.Error("failed to dump request", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	connID, err := generateTunnelID()
	if err != nil {
		p.logger.Error("failed to generate conn ID", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	proxiedConn := NewProxiedConn(connID, rawHead)

	// Register and ensure cleanup on all exit paths.
	tunnel.pending.Store(connID, proxiedConn)
	defer func() {
		proxiedConn.Close()
		tunnel.pending.Delete(connID)
	}()

	if err := tunnel.WriteData(protocol.BinTypeData, protocol.TypeData, connID, rawHead); err != nil {
		p.logger.Error("failed to write to tunnel", "error", err, "tunnel_id", tunnel.ID)
		http.Error(w, "Tunnel communication error", http.StatusBadGateway)
		return
	}

	// Pump the request body to the client while we read the response back.
	// A backend may answer before the upload finishes (a 413, a redirect), so
	// these have to run concurrently.
	bodyDone := make(chan struct{})
	go func() {
		defer close(bodyDone)
		p.streamRequestBody(w, r, tunnel, connID)
	}()

	// Stream response events to the public caller. No overall timeout — long
	// streams (SSE, LLM generation) can legitimately run for minutes. We bound
	// only the time-to-first-event, and forward public-caller cancellation
	// upstream via a close frame with reason=cancel.
	p.streamResponse(w, r, tunnel, proxiedConn)

	// Drain the upload before releasing the connection, so the pump goroutine
	// never touches r.Body after the handler returns.
	<-bodyDone
}

// streamRequestBody forwards the request body to the tunnel client in chunks,
// then signals end-of-request. Oversize chunked uploads are reported to the
// tunnel owner and terminated.
func (p *ProxyHandler) streamRequestBody(w http.ResponseWriter, r *http.Request, tunnel *Tunnel, connID string) {
	buf := make([]byte, reqChunkSize)
	for {
		n, readErr := r.Body.Read(buf)
		if n > 0 {
			if err := tunnel.WriteData(protocol.BinTypeReqBody, protocol.TypeReqBody, connID, buf[:n]); err != nil {
				p.logger.Debug("request body write failed", "error", err, "conn_id", connID)
				return
			}
		}
		if readErr != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(readErr, &maxBytesErr) {
				// The caller exceeded the cap on a body of unknown length.
				p.notifyBodyTooLarge(tunnel, r, -1)
				p.sendClose(tunnel, connID, protocol.CloseReasonCancel)
				return
			}
			if readErr != io.EOF {
				p.logger.Debug("request body read ended", "error", readErr, "conn_id", connID)
				p.sendClose(tunnel, connID, protocol.CloseReasonCancel)
				return
			}
			break
		}
	}

	if tunnel.Binary {
		if err := tunnel.WriteData(protocol.BinTypeReqEnd, protocol.TypeReqEnd, connID, nil); err != nil {
			p.logger.Debug("request end write failed", "error", err, "conn_id", connID)
		}
		return
	}
	if err := tunnel.WriteControl(protocol.TypeReqEnd, &protocol.CloseFrame{
		ConnID:   connID,
		TunnelID: tunnel.ID,
	}); err != nil {
		p.logger.Debug("request end write failed", "error", err, "conn_id", connID)
	}
}

// streamResponse consumes events from the ProxiedConn and writes them to the
// public HTTP response in real time. It also watches the request context and
// tunnel liveness so upstream cancellation propagates correctly.
func (p *ProxyHandler) streamResponse(w http.ResponseWriter, r *http.Request, tunnel *Tunnel, pc *ProxiedConn) {
	flusher, _ := w.(http.Flusher)
	headersWritten := false

	// Watch for public-caller cancel and forward it upstream as a close frame.
	// We use a local done channel (not r.Context()) to distinguish "public
	// caller disconnected mid-stream" from "handler returning after a clean
	// finish" — net/http cancels r.Context() on normal return too, which
	// would otherwise produce a spurious cancel on every successful request.
	doneCh := make(chan struct{})
	defer close(doneCh)
	reqCtx := r.Context()
	go func() {
		select {
		case <-reqCtx.Done():
			// Only forward cancel if streamResponse is still in progress.
			select {
			case <-doneCh:
				// Normal completion — no cancel needed.
			default:
				p.sendClose(tunnel, pc.ID, protocol.CloseReasonCancel)
			}
		case <-tunnel.done:
		case <-doneCh:
		}
	}()

	firstEventTimer := time.NewTimer(p.firstEventTimeout)
	defer firstEventTimer.Stop()

	for {
		select {
		case ev, ok := <-pc.Events:
			if !ok {
				// Channel closed without a proper end event: either the tunnel
				// died, or the event buffer overflowed and chunks were dropped.
				if !headersWritten {
					http.Error(w, "Tunnel closed during request", http.StatusBadGateway)
					return
				}
				// Headers are already out, so the caller would otherwise read a
				// truncated body as a complete one. Abort the response instead:
				// net/http drops the connection without a terminating chunk, so
				// the transfer is seen as broken, which it is.
				p.logger.Error("response truncated before end of stream",
					"conn_id", pc.ID,
					"tunnel_id", tunnel.ID,
					"overflowed", pc.Overflowed(),
				)
				panic(http.ErrAbortHandler)
			}
			// Reset the first-event timer on any activity — once the stream is
			// live, there's no overall deadline.
			if !firstEventTimer.Stop() {
				select {
				case <-firstEventTimer.C:
				default:
				}
			}

			switch ev.Kind {
			case ProxyEventHeader:
				if ev.Header.StatusCode == 0 {
					// Legacy TypeData path: the "header" is just a marker,
					// the body chunk carries the full raw HTTP response.
					continue
				}
				copyResponseHeaders(w, ev.Header.Headers)
				w.Header().Set("X-Mabo-Tunnel-Tunnel", tunnel.ID)
				w.WriteHeader(ev.Header.StatusCode)
				headersWritten = true
				if flusher != nil {
					flusher.Flush()
				}

			case ProxyEventBody:
				pc.release(len(ev.Body))
				if !headersWritten {
					// Legacy path: raw HTTP response bytes. Parse and stream.
					p.writeRawResponse(w, r, ev.Body, tunnel.ID)
					headersWritten = true
					continue
				}
				if len(ev.Body) > 0 {
					if _, err := w.Write(ev.Body); err != nil {
						// Public caller went away — the context-watcher goroutine
						// already sent cancel upstream.
						return
					}
					if flusher != nil {
						flusher.Flush()
					}
				}

			case ProxyEventEnd:
				if !headersWritten && ev.EndReason != "" {
					http.Error(w, "Upstream error: "+ev.EndReason, http.StatusBadGateway)
					return
				}
				if headersWritten && ev.EndReason != "" && ev.EndReason != "canceled" {
					// The backend failed partway through a response we have
					// already started. Same reasoning as above: end the
					// transfer visibly rather than cleanly.
					p.logger.Error("upstream error mid-response",
						"conn_id", pc.ID,
						"tunnel_id", tunnel.ID,
						"reason", ev.EndReason,
					)
					panic(http.ErrAbortHandler)
				}
				return
			}

		case <-firstEventTimer.C:
			if !headersWritten {
				p.sendClose(tunnel, pc.ID, protocol.CloseReasonCancel)
				http.Error(w, fmt.Sprintf("Upstream timeout (no response headers within %s)", p.firstEventTimeout), http.StatusGatewayTimeout)
				return
			}

		case <-tunnel.done:
			if !headersWritten {
				http.Error(w, "Tunnel closed during request", http.StatusBadGateway)
				return
			}
			panic(http.ErrAbortHandler)
		}
	}
}

// sendClose tells the tunnel client to close or abort a logical connection.
func (p *ProxyHandler) sendClose(tunnel *Tunnel, connID, reason string) {
	_ = tunnel.WriteControl(protocol.TypeClose, &protocol.CloseFrame{
		ConnID:   connID,
		TunnelID: tunnel.ID,
		Reason:   reason,
	})
}

// handleWebSocketProxy handles a WebSocket upgrade request by hijacking the
// connection and using bidirectional streaming through the tunnel.
func (p *ProxyHandler) handleWebSocketProxy(w http.ResponseWriter, r *http.Request, tunnel *Tunnel) {
	// An upgrade request holds a slot in the small upgrade-pending pool until
	// the tunnel peer answers; an established passthrough moves back to the
	// general in-flight budget. Without this, a caller who only sends upgrade
	// requests and never completes a handshake could hold the tunnel's whole
	// 200-request budget and take a live tunnel offline (F-03).
	if n := tunnel.upgradePending.Add(1); n > maxUpgradePendingPerTunnel {
		tunnel.upgradePending.Add(-1)
		p.logger.Warn("tunnel at WebSocket upgrade limit",
			"tunnel_id", tunnel.ID,
			"limit", maxUpgradePendingPerTunnel,
		)
		http.Error(w, "Tunnel is at its WebSocket upgrade limit", http.StatusServiceUnavailable)
		return
	}
	slotHeld := true
	defer func() {
		if slotHeld {
			tunnel.upgradePending.Add(-1)
		}
	}()

	connID, err := generateTunnelID()
	if err != nil {
		p.logger.Error("failed to generate ws conn ID", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	p.logger.Debug("proxying WebSocket upgrade",
		"conn_id", connID,
		"tunnel_id", tunnel.ID,
		"path", r.URL.Path,
	)

	// Dump the raw upgrade request to forward to the client. An upgrade has no
	// body, so the head is the whole request; the caller already sanitized the
	// headers and stamped the verified origin.
	rawReq, err := httputil.DumpRequest(r, false)
	if err != nil {
		p.logger.Error("failed to dump WebSocket request", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create a streaming proxied connection with a larger buffered channel
	// for continuous bidirectional data flow.
	proxiedConn := &StreamingConn{
		ID:      connID,
		DataCh:  make(chan []byte, streamingConnBuffer),
		CloseCh: make(chan struct{}),
	}
	tunnel.pending.Store(connID, proxiedConn)
	defer func() {
		proxiedConn.Close()
		tunnel.pending.Delete(connID)
	}()

	if err := tunnel.WriteData(protocol.BinTypeData, protocol.TypeData, connID, rawReq); err != nil {
		p.logger.Error("failed to write ws request to tunnel", "error", err)
		http.Error(w, "Tunnel communication error", http.StatusBadGateway)
		return
	}

	// Wait for the peer's upgrade response under a short deadline: a live
	// local server answers in milliseconds, and every second of wait is a
	// slot an attacker can hold.
	var firstResponse []byte
	select {
	case firstResponse = <-proxiedConn.DataCh:
		proxiedConn.release(len(firstResponse))
	case <-proxiedConn.CloseCh:
		http.Error(w, "Tunnel closed during WebSocket upgrade", http.StatusBadGateway)
		return
	case <-tunnel.done:
		http.Error(w, "Tunnel closed during WebSocket upgrade", http.StatusBadGateway)
		return
	case <-time.After(wsUpgradeTimeout):
		http.Error(w, "WebSocket upgrade timeout", http.StatusGatewayTimeout)
		return
	}
	// The handshake answered; the connection is no longer pending.
	slotHeld = false
	tunnel.upgradePending.Add(-1)

	// The tunnel peer is untrusted code: nothing but a well-formed 101 head
	// may reach the visitor as the HTTP response. Forwarding its bytes
	// verbatim would let it emit an arbitrary status line or a whole second
	// response into a connection the edge has stopped parsing (S-18/D-018).
	upgradeHead, upgradeTail, ok := parseUpgradeResponse(firstResponse)
	if !ok {
		p.logger.Warn("tunnel peer did not answer a WebSocket upgrade with 101",
			"tunnel_id", tunnel.ID,
			"conn_id", connID,
		)
		http.Error(w, "Tunnel peer did not complete the WebSocket upgrade", http.StatusBadGateway)
		return
	}

	// Hijack the HTTP connection to get raw TCP access.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket hijack not supported", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		p.logger.Error("failed to hijack connection", "error", err)
		return
	}
	defer clientConn.Close()

	// Clear any deadline net/http left on the connection; from here the
	// lifetime is the WebSocket's, not the HTTP request's.
	clientConn.SetDeadline(time.Time{})

	// Write the peer's validated 101 head, followed by any post-upgrade bytes
	// that arrived with it (a server may send its first frame immediately).
	if _, err := clientConn.Write(upgradeHead); err != nil {
		p.logger.Error("failed to write upgrade response", "error", err)
		return
	}
	if len(upgradeTail) > 0 {
		if _, err := clientConn.Write(upgradeTail); err != nil {
			p.logger.Error("failed to write post-upgrade data", "error", err)
			return
		}
	}
	clientBuf.Flush()

	// Bidirectional streaming:
	// 1. Browser → tunnel client: read from hijacked conn, send via WebSocket tunnel
	// 2. Tunnel client → browser: receive from DataCh, write to hijacked conn

	done := make(chan struct{})

	// Browser → tunnel client
	go func() {
		defer func() {
			select {
			case <-done:
			default:
				close(done)
			}
		}()
		buf := make([]byte, 32*1024)
		for {
			n, readErr := clientConn.Read(buf)
			if n > 0 {
				if err := tunnel.WriteData(protocol.BinTypeData, protocol.TypeData, connID, buf[:n]); err != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	// Tunnel client → browser
	for {
		select {
		case data, ok := <-proxiedConn.DataCh:
			if !ok {
				return
			}
			proxiedConn.release(len(data))
			if _, err := clientConn.Write(data); err != nil {
				return
			}
		case <-proxiedConn.CloseCh:
			return
		case <-tunnel.done:
			return
		case <-done:
			return
		}
	}
}

// parseUpgradeResponse validates that a tunnel peer's first bytes are an HTTP
// 101 response and splits the response head from any post-upgrade bytes that
// followed it. The peer is untrusted code, so only a well-formed 101 head may
// reach the visitor as the HTTP response.
func parseUpgradeResponse(data []byte) (head, tail []byte, ok bool) {
	src := bytes.NewReader(data)
	br := bufio.NewReader(src)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, nil, false
	}
	consumed := len(data) - src.Len() - br.Buffered()
	return data[:consumed], data[consumed:], true
}

// copyResponseHeaders writes a tunnel peer's response headers onto the public
// response, minus what must not cross a proxy hop.
//
// Hop-by-hop headers (plus anything the peer names in its own Connection
// header) describe a connection the peer does not share with the public
// caller, so forwarding them lets a tunnel peer dictate edge-connection
// semantics. The peer's Content-Length is dropped too: the framing of the
// public response comes from the body bytes actually forwarded, not from a
// length a peer asserts — a mismatched one otherwise truncates or corrupts
// the transfer.
func copyResponseHeaders(w http.ResponseWriter, headers map[string][]string) {
	named := connectionNamedHeaders(headers)
	for key, vals := range headers {
		canonical := http.CanonicalHeaderKey(key)
		if protocol.HopByHopHeaders[canonical] || named[canonical] || canonical == "Content-Length" {
			continue
		}
		for _, val := range vals {
			w.Header().Add(canonical, val)
		}
	}
}

// connectionNamedHeaders returns the header names a Connection header value
// declares as per-connection, canonicalized.
func connectionNamedHeaders(headers map[string][]string) map[string]bool {
	var named map[string]bool
	for _, val := range headers["Connection"] {
		for _, tok := range strings.Split(val, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if named == nil {
				named = make(map[string]bool)
			}
			named[http.CanonicalHeaderKey(tok)] = true
		}
	}
	return named
}

// stripHopByHopRequest removes request headers that describe the caller's
// connection rather than the request itself, plus every header the caller's
// Connection header names. Without this, `Connection: X-Secret` makes
// X-Secret hop-by-hop and a tunnel peer that forwards it into the app's
// request stream would turn the caller's connection metadata into an app
// header. The upgrade pair (Connection, Upgrade) is preserved for genuine
// upgrades so the tunneled server can complete the handshake.
func stripHopByHopRequest(r *http.Request, isUpgrade bool) {
	named := connectionNamedHeaders(r.Header)
	for key := range r.Header {
		canonical := http.CanonicalHeaderKey(key)
		if !protocol.HopByHopHeaders[canonical] && !named[canonical] {
			continue
		}
		if isUpgrade && (canonical == "Connection" || canonical == "Upgrade") {
			continue
		}
		r.Header.Del(key)
	}
}

// writeRawResponse handles the legacy TypeData path where the tunnel client
// sent the entire HTTP response as a single buffered blob. It parses the blob
// and streams the body with flushes, same as before.
func (p *ProxyHandler) writeRawResponse(w http.ResponseWriter, r *http.Request, data []byte, tunnelID string) int {
	// Try to parse as a proper HTTP response.
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), r)
	if err != nil {
		// Not a valid HTTP response — write as plain body.
		w.Header().Set("X-Mabo-Tunnel-Tunnel", tunnelID)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
		return http.StatusOK
	}
	defer resp.Body.Close()

	copyResponseHeaders(w, resp.Header)
	w.Header().Set("X-Mabo-Tunnel-Tunnel", tunnelID)

	w.WriteHeader(resp.StatusCode)

	// Stream body with bounded buffer.
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		if readErr != nil {
			break
		}
	}
	return resp.StatusCode
}

// hostWithoutPort strips a port from a Host header value, handling IPv6
// literals correctly (net.SplitHostPort fails on a bare host, which is fine).
func hostWithoutPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	// No port present. Unwrap a bracketed IPv6 literal if there is one.
	return strings.Trim(host, "[]")
}

// normalizeHost canonicalizes a Host header value: lowercase (DNS names are
// case-insensitive), no trailing dot, no port. A malformed or out-of-range
// port yields "" — the request then names no tunnel rather than one chosen by
// whatever the caller typed. Every host-keyed lookup runs on this form.
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if h, port, err := net.SplitHostPort(host); err == nil {
		if port != "" {
			if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				return ""
			}
		}
		host = h
	} else {
		host = strings.Trim(host, "[]")
	}
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

func (p *ProxyHandler) extractSubdomain(host string) string {
	host = normalizeHost(host)

	suffix := "." + p.domain
	if !strings.HasSuffix(host, suffix) {
		return ""
	}

	subdomain := strings.TrimSuffix(host, suffix)
	if subdomain == "" || strings.Contains(subdomain, ".") {
		return ""
	}

	return registeredSubdomain(subdomain)
}

// checkIPAccess validates the requester's IP against the tunnel's deny and
// allow lists. Deny list is checked first. If the allow list is non-empty,
// only listed networks are permitted. Both lists hold CIDRs; a bare IP was
// normalized to /32 or /128 at the handshake.
func (p *ProxyHandler) checkIPAccess(r *http.Request, tunnel *Tunnel) bool {
	clientIP := p.extractClientIP(r)
	if tunnel.ipAllowed(net.ParseIP(clientIP)) {
		return true
	}
	p.logger.Warn("requester IP is not allowed to access tunnel",
		"ip", clientIP,
		"tunnel_id", tunnel.ID,
	)
	return false
}

// setForwardedFor appends the verified requester origin to the request's
// X-Forwarded-For chain before the head is forwarded through the tunnel.
//
// Every proxy hop appends the address it received the request from, without
// rewriting what earlier hops recorded, so the rightmost entry is the hop
// closest to this edge — the one an app behind the tunnel can act on. The old
// version read only the first X-Forwarded-For header, replaced the whole chain
// with it, and appended a second copy of the address derived for rate limiting.
func (p *ProxyHandler) setForwardedFor(r *http.Request) {
	remote := hostWithoutPort(r.RemoteAddr)
	if remote == "" {
		return
	}
	chain := append([]string(nil), r.Header.Values("X-Forwarded-For")...)
	chain = append(chain, remote)
	r.Header.Set("X-Forwarded-For", strings.Join(chain, ", "))
}

// setForwardedProto stamps the scheme the request arrived with so the tunneled
// app does not have to guess. An operator-declared trusted proxy may describe
// it (TLS often terminates there); otherwise the scheme comes from this
// connection and a caller-supplied value is discarded.
func (p *ProxyHandler) setForwardedProto(r *http.Request) {
	proto := ""
	if p.isTrustedProxy(hostWithoutPort(r.RemoteAddr)) {
		proto = strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	}
	if proto != "http" && proto != "https" {
		proto = "http"
		if r.TLS != nil {
			proto = "https"
		}
	}
	r.Header.Set("X-Forwarded-Proto", proto)
}

// notifyBodyTooLarge sends an out-of-band notice to the tunnel owner so the
// client TUI can surface the rejected upload. size < 0 means the size wasn't
// known in advance (e.g. chunked transfer that overran the limit mid-stream).
func (p *ProxyHandler) notifyBodyTooLarge(tunnel *Tunnel, r *http.Request, size int64) {
	msg := fmt.Sprintf("Request rejected: body exceeds %d bytes tunnel limit", maxRequestBodySize)
	if size > 0 {
		msg = fmt.Sprintf("Request rejected: body is %d bytes, exceeds %d bytes tunnel limit", size, maxRequestBodySize)
	}
	notice := &protocol.Notice{
		Level:   "warn",
		Code:    protocol.NoticeCodeBodyTooLarge,
		Message: msg,
		Method:  r.Method,
		Path:    r.URL.Path,
		Size:    size,
		Limit:   maxRequestBodySize,
	}
	p.logger.Warn("upload rejected: body too large",
		"tunnel_id", tunnel.ID,
		"method", r.Method,
		"path", r.URL.Path,
		"size", size,
		"limit", maxRequestBodySize,
	)

	_ = tunnel.WriteControl(protocol.TypeNotice, notice)
}

// checkBasicAuth validates the request's Authorization header against the tunnel's
// configured "user:pass" credentials using constant-time comparison.
func (p *ProxyHandler) checkBasicAuth(r *http.Request, credentials string) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return false
	}
	userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(parts[0])) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(parts[1])) == 1
	return userMatch && passMatch
}

// isTrustedProxy reports whether an address is one of the hops we allow to
// describe the origin of a request.
func (p *ProxyHandler) isTrustedProxy(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range p.trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// extractClientIP returns the requester's origin address.
//
// X-Forwarded-For is caller-supplied data. It is honored only when the request
// reached us from a trusted hop, and the chain is then walked from the right,
// skipping further trusted hops — the first address we do not trust is the
// closest thing to the real client. Anything else lets a caller pick its own
// address and walk straight through an allow list.
func (p *ProxyHandler) extractClientIP(r *http.Request) string {
	remote := hostWithoutPort(r.RemoteAddr)

	if !p.isTrustedProxy(remote) {
		return remote
	}

	fwd := r.Header.Get("X-Forwarded-For")
	if fwd == "" {
		return remote
	}

	parts := strings.Split(fwd, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if ip == "" || p.isTrustedProxy(ip) {
			continue
		}
		if net.ParseIP(ip) == nil {
			continue
		}
		return ip
	}

	return remote
}
