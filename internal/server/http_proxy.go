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
	"strings"
	"time"

	"github.com/maborak/mabo-tunnel/internal/protocol"
)

// Max request body size (10 MB).
const maxRequestBodySize = 10 * 1024 * 1024

// reqChunkSize is how much request body is forwarded per frame.
const reqChunkSize = 32 * 1024

// defaultTrustedProxies are the ranges an X-Forwarded-For header is honored
// from when none are configured: loopback and the private ranges a reverse
// proxy or container network lives on. A request arriving directly from the
// public internet is never trusted to describe its own origin.
var defaultTrustedProxies = []string{
	"127.0.0.0/8", "::1/128",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"fc00::/7",
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
// CIDRs whose X-Forwarded-For headers are believed; empty means the defaults.
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
		domain:            domain,
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
	subdomain := p.extractSubdomain(r.Host)
	if subdomain == "" {
		// Not a <subdomain>.<base-domain> request — try a registered custom
		// hostname before giving up.
		tunnel, customOk := p.tunnels.LookupCustom(hostWithoutPort(r.Host))
		if !customOk {
			http.Error(w, "No tunnel specified. Use <subdomain>."+p.domain, http.StatusBadRequest)
			return
		}
		subdomain = tunnel.Subdomain
	}

	tunnel, ok := p.tunnels.LookupByHost(subdomain)
	if !ok {
		http.Error(w, fmt.Sprintf("Tunnel %q not found. It may have been closed.", subdomain), http.StatusNotFound)
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
	}

	// Per-tunnel request-rate cap. The bucket belongs to the tunnel, so the
	// limit travels with the tunnel across reconnects and is shared by every
	// concurrent public caller hammering it.
	if tunnel.rateLimiter != nil && !tunnel.rateLimiter.allow() {
		p.metrics.Inc("mabo_http_responses_total", statusClass(429))
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

	// WebSocket upgrade requests get special bidirectional handling.
	if isWebSocketUpgrade(r) {
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
		"subdomain", subdomain,
		"method", r.Method,
		"path", r.URL.Path,
		"tunnel_id", tunnel.ID,
	)

	// Forward the request head only. The body streams behind it as its own
	// frames, so a large upload starts reaching the local server immediately
	// instead of being buffered whole at the edge first.
	//
	// Record the origin first: the head carries whatever X-Forwarded-For the
	// caller (or an edge proxy) supplied, and the app behind the tunnel has
	// no other way to learn an address this server actually verified.
	p.setForwardedFor(r)
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
				w.Header().Set("X-Mabo Tunnel-Tunnel", tunnel.ID)
				w.WriteHeader(ev.Header.StatusCode)
				headersWritten = true
				p.metrics.Inc("mabo_http_responses_total", statusClass(ev.Header.StatusCode))
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
	// body, so the head is the whole request. Set the verified origin first,
	// same as the plain proxy path.
	p.setForwardedFor(r)
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

	// Wait for the initial response (the 101 Switching Protocols + subsequent data).
	// First response contains the HTTP 101 upgrade response.
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
	case <-time.After(30 * time.Second):
		http.Error(w, "WebSocket upgrade timeout", http.StatusGatewayTimeout)
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

	// Write the initial upgrade response to the browser/client.
	if _, err := clientConn.Write(firstResponse); err != nil {
		p.logger.Error("failed to write upgrade response", "error", err)
		return
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

// writeRawResponse handles the legacy TypeData path where the tunnel client
// sent the entire HTTP response as a single buffered blob. It parses the blob
// and streams the body with flushes, same as before.
func (p *ProxyHandler) writeRawResponse(w http.ResponseWriter, r *http.Request, data []byte, tunnelID string) int {
	// Try to parse as a proper HTTP response.
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), r)
	if err != nil {
		// Not a valid HTTP response — write as plain body.
		w.Header().Set("X-Mabo Tunnel-Tunnel", tunnelID)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
		return http.StatusOK
	}
	defer resp.Body.Close()

	copyResponseHeaders(w, resp.Header)
	w.Header().Set("X-Mabo Tunnel-Tunnel", tunnelID)

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

func (p *ProxyHandler) extractSubdomain(host string) string {
	host = hostWithoutPort(host)

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
	if len(tunnel.deniedNets) == 0 && len(tunnel.allowedNets) == 0 {
		return true
	}

	clientIP := net.ParseIP(p.extractClientIP(r))
	if clientIP == nil {
		// We could not establish an origin. With an allow list configured the
		// safe answer is no.
		return len(tunnel.allowedNets) == 0
	}

	// Check deny list first.
	for _, denied := range tunnel.deniedNets {
		if denied.Contains(clientIP) {
			p.logger.Warn("IP denied by deny list",
				"ip", clientIP.String(),
				"cidr", denied.String(),
				"tunnel_id", tunnel.ID,
			)
			return false
		}
	}

	// If allow list is non-empty, only listed networks are permitted.
	if len(tunnel.allowedNets) > 0 {
		for _, allowed := range tunnel.allowedNets {
			if allowed.Contains(clientIP) {
				return true
			}
		}
		p.logger.Warn("IP not in allow list",
			"ip", clientIP.String(),
			"tunnel_id", tunnel.ID,
		)
		return false
	}

	return true
}

// setForwardedFor appends the verified requester origin to the request's
// X-Forwarded-For chain before the head is forwarded through the tunnel.
//
// Every proxy hop appends the address it received the request from; that is
// the contract apps behind the tunnel read (rightmost = closest proxy, and
// ours is the one this server controls). Without this, the chain the caller
// typed arrives untouched and an app trusting it authenticates whichever IP
// the caller chose.
func (p *ProxyHandler) setForwardedFor(r *http.Request) {
	clientIP := p.extractClientIP(r)
	if clientIP == "" {
		return
	}
	if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
		r.Header.Set("X-Forwarded-For", prior+", "+clientIP)
	} else {
		r.Header.Set("X-Forwarded-For", clientIP)
	}
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
