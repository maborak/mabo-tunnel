package server

import (
	"log/slog"
	"time"

	"github.com/maborak/mabo-tunnel/internal/auth"
	"github.com/maborak/mabo-tunnel/internal/protocol"

	"github.com/gorilla/websocket"
)

// authResult holds the result of a successful authentication.
type authResult struct {
	User       *auth.User
	SessionID  string
	Name       string
	Subdomain  string
	Protocol   string   // "http" or "tcp"
	AllowedIPs []string // IP allow list from client
	DeniedIPs  []string // IP deny list from client
	BasicAuth  string   // "user:pass" for HTTP Basic Auth on the tunnel
	Binary     bool     // client understands binary data frames
}

// handleAuth processes an auth_request message on a new WebSocket connection.
// Returns the auth result or nil if authentication failed.
func handleAuth(conn *websocket.Conn, users *auth.UserStore, limiter *auth.RateLimiter, remoteAddr string, logger *slog.Logger) *authResult {
	// Set deadline for auth handshake.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{}) // clear after auth

	// Rate limit check.
	if !limiter.Allow(remoteAddr) {
		logger.Warn("auth rate limited", "ip", remoteAddr)
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

	// Validate the token (constant-time comparison inside).
	user, ok := users.Authenticate(authReq.Token)
	if !ok {
		limiter.Record(remoteAddr)
		logger.Warn("authentication failed", "ip", remoteAddr)
		sendAuthResponse(conn, false, "Invalid token", nil)
		return nil
	}

	logger.Info("authenticated", "username", user.Username, "plan", user.Plan)
	return &authResult{
		User:       user,
		SessionID:  authReq.SessionID,
		Name:       authReq.Name,
		Subdomain:  authReq.Subdomain,
		Protocol:   authReq.Protocol,
		AllowedIPs: authReq.AllowedIPs,
		DeniedIPs:  authReq.DeniedIPs,
		BasicAuth:  authReq.BasicAuth,
		Binary:     authReq.Binary,
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
