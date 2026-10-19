package server

import (
	"log/slog"
	"strings"
	"time"

	"github.com/maborak/mabo-tunnel/internal/auth"
	"github.com/maborak/mabo-tunnel/internal/protocol"

	"github.com/gorilla/websocket"
)

// maxSessionIDLen bounds the reconnect session identifier a client may send:
// it keys a reservation entry and is echoed into logs, and no legitimate
// client needs more than a short opaque identifier.
const maxSessionIDLen = 128

// authResult holds the result of a successful authentication.
type authResult struct {
	User         *auth.User
	SessionID    string
	Name         string
	Subdomain    string
	Protocol     string   // "http" or "tcp"
	AllowedIPs   []string // IP allow list from client
	DeniedIPs    []string // IP deny list from client
	BasicAuth    string   // "user:pass" for HTTP Basic Auth on the tunnel
	CustomDomain string   // custom hostname request (verified before registration)
	TokenKey     [32]byte // hash of the presented token, for challenge derivation
	Binary       bool     // client understands binary data frames
}

// handleAuth processes an auth_request message on a new WebSocket connection.
// Returns the auth result or nil if authentication failed.
func handleAuth(conn *websocket.Conn, users *auth.UserStore, limiter *auth.RateLimiter, remoteAddr string, logger *slog.Logger, metrics *Metrics) *authResult {
	// Set deadline for auth handshake.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{}) // clear after auth

	// fail counts the handshake as rejected and answers the client. Every
	// rejection path goes through it: a failure the metric cannot see is a
	// blind spot in exactly the situation an operator is watching for.
	fail := func(message string) *authResult {
		metrics.Inc("mabo_auth_failures_total", "")
		sendAuthResponse(conn, false, message, nil)
		return nil
	}

	_, msg, err := conn.ReadMessage()
	if err != nil {
		logger.Error("failed to read auth message", "error", err)
		return fail("Failed to read auth message")
	}

	env, err := protocol.ParseEnvelope(msg)
	if err != nil {
		logger.Error("failed to parse auth envelope", "error", err)
		return fail("Invalid message format")
	}

	if env.Type != protocol.TypeAuthRequest {
		logger.Warn("expected auth_request", "got", env.Type)
		return fail("Expected auth_request as first message")
	}

	var authReq protocol.AuthRequest
	if err := env.ParsePayload(&authReq); err != nil {
		logger.Error("failed to parse auth request", "error", err)
		return fail("Invalid auth request")
	}

	// A well-formed auth_request is one credential guess. Count and bound it
	// in one atomic step, before the token is checked, so parallel guesses
	// cannot each observe the same pre-attempt state and slip through
	// together. A successful authentication refunds the slot below, so only
	// failures accumulate — and a connection that never presents a guess is
	// not charged for one.
	if !limiter.Take(remoteAddr) {
		logger.Warn("auth rate limited", "ip", remoteAddr)
		metrics.Inc("mabo_auth_failures_total", "")
		metrics.Inc("mabo_auth_rate_limited_total", "")
		sendAuthResponse(conn, false, "Too many auth attempts, try again later", nil)
		return nil
	}
	metrics.Inc("mabo_auth_attempts_total", "")

	if authReq.Token == "" {
		return fail("Token is required")
	}

	// Validate the token (constant-time comparison inside).
	user, ok := users.Authenticate(authReq.Token)
	if !ok {
		logger.Warn("authentication failed", "ip", remoteAddr)
		return fail("Invalid token")
	}
	limiter.Refund(remoteAddr)

	// A session ID keys a reconnect reservation and is echoed into logs; no
	// legitimate client needs more than a short opaque identifier.
	if len(authReq.SessionID) > maxSessionIDLen {
		return fail("session_id too long (max 128 characters)")
	}

	logger.Info("authenticated", "username", user.Username, "plan", user.Plan)

	// Normalize and validate the IP filter lists before they reach the tunnel
	// registry: bad values die at the handshake with a clear message instead
	// of mis-filtering traffic later.
	allowedIPs, err := protocol.NormalizeIPList(authReq.AllowedIPs, "allowed_ips")
	if err != nil {
		sendAuthResponse(conn, false, err.Error(), nil)
		return nil
	}
	deniedIPs, err := protocol.NormalizeIPList(authReq.DeniedIPs, "denied_ips")
	if err != nil {
		sendAuthResponse(conn, false, err.Error(), nil)
		return nil
	}

	return &authResult{
		User:         user,
		SessionID:    authReq.SessionID,
		Name:         authReq.Name,
		Subdomain:    authReq.Subdomain,
		Protocol:     authReq.Protocol,
		AllowedIPs:   allowedIPs,
		DeniedIPs:    deniedIPs,
		BasicAuth:    authReq.BasicAuth,
		CustomDomain: strings.TrimSpace(authReq.CustomDomain),
		TokenKey:     func() [32]byte { k, _ := users.TokenKey(authReq.Token); return k }(),
		Binary:       authReq.Binary,
	}
}

func sendAuthResponse(conn *websocket.Conn, success bool, message string, resp *protocol.AuthResponse) {
	if resp == nil {
		resp = &protocol.AuthResponse{
			Success: success,
			Message: message,
		}
	}

	env, err := protocol.NewEnvelope(protocol.TypeAuthResponse, resp)
	if err != nil {
		return
	}

	msgBytes, err := env.Marshal()
	if err != nil {
		return
	}

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	conn.WriteMessage(websocket.TextMessage, msgBytes)
	conn.SetWriteDeadline(time.Time{})
}
