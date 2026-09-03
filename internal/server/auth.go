package server

import (
	"log/slog"
	"strings"
	"time"

	"github.com/maborak/mabo-tunnel/internal/auth"
	"github.com/maborak/mabo-tunnel/internal/protocol"

	"github.com/gorilla/websocket"
)

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

	// Rate limit check.
	if !limiter.Allow(remoteAddr) {
		logger.Warn("auth rate limited", "ip", remoteAddr)
		// Drain the pending auth frame before rejecting: closing a
		// connection that still has unread inbound data sends an abortive
		// reset, and on Windows that reset destroys the rejection response
		// before it reaches the peer.
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, _ = conn.ReadMessage()
		sendAuthResponse(conn, false, "Too many auth attempts, try again later", nil)
		return nil
	}

	_, msg, err := conn.ReadMessage()
	if err != nil {
		logger.Error("failed to read auth message", "error", err)
		sendAuthResponse(conn, false, "Failed to read auth message", nil)
		return nil
	}

	env, err := protocol.ParseEnvelope(msg)
	if err != nil {
		logger.Error("failed to parse auth envelope", "error", err)
		sendAuthResponse(conn, false, "Invalid message format", nil)
		return nil
	}

	if env.Type != protocol.TypeAuthRequest {
		logger.Warn("expected auth_request", "got", env.Type)
		sendAuthResponse(conn, false, "Expected auth_request as first message", nil)
		return nil
	}

	var authReq protocol.AuthRequest
	if err := env.ParsePayload(&authReq); err != nil {
		logger.Error("failed to parse auth request", "error", err)
		sendAuthResponse(conn, false, "Invalid auth request", nil)
		return nil
	}

	if authReq.Token == "" {
		sendAuthResponse(conn, false, "Token is required", nil)
		return nil
	}

	metrics.Inc("mabo_auth_attempts_total", "")

	// Validate the token (constant-time comparison inside).
	user, ok := users.Authenticate(authReq.Token)
	if !ok {
		limiter.Record(remoteAddr)
		logger.Warn("authentication failed", "ip", remoteAddr)
		metrics.Inc("mabo_auth_failures_total", "")
		sendAuthResponse(conn, false, "Invalid token", nil)
		return nil
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
