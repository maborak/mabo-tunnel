package server

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/maborak/mabo-tunnel/internal/version"
)

// adminTunnel is the JSON shape of one tunnel in /admin/tunnels.
type adminTunnel struct {
	ID          string   `json:"id"`
	Subdomain   string   `json:"subdomain"`
	URL         string   `json:"url"`
	Username    string   `json:"username"`
	Plan        string   `json:"plan"`
	Protocol    string   `json:"protocol"`
	TCPPort     int      `json:"tcp_port,omitempty"`
	ConnectedAt string   `json:"connected_at"`
	InFlight    int64    `json:"in_flight"`
	AllowedIPs  []string `json:"allowed_ips,omitempty"`
	DeniedIPs   []string `json:"denied_ips,omitempty"`
	BasicAuth   bool     `json:"basic_auth"`
}

// authorizeAdmin checks the admin bearer token. A server without
// --admin-token answers 404 to everything, so probing cannot even learn that
// an admin API exists.
func (s *Server) authorizeAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.config.AdminToken == "" {
		http.NotFound(w, r)
		return false
	}
	token := r.Header.Get("X-Admin-Token")
	if auth := r.Header.Get("Authorization"); len(auth) > 7 && auth[:7] == "Bearer " {
		token = auth[7:]
	}
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.config.AdminToken)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="mabo-tunnel-admin"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *Server) tunnelURL(t *Tunnel) string {
	if t.Protocol == "tcp" {
		return "tcp://" + s.config.Domain + ":" + strconv.Itoa(t.TCPPort)
	}
	if t.CustomHost != "" {
		return s.effectiveScheme() + "://" + t.CustomHost
	}
	if t.Subdomain == "" {
		return ""
	}
	return s.tunnels.URL(t.Subdomain, s.effectiveScheme())
}

func (s *Server) handleAdminTunnels(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tunnels := s.tunnels.List()
	out := make([]adminTunnel, 0, len(tunnels))
	for _, t := range tunnels {
		out = append(out, adminTunnel{
			ID:          t.ID,
			Subdomain:   t.Subdomain,
			URL:         s.tunnelURL(t),
			Username:    t.Username,
			Plan:        t.Plan,
			Protocol:    t.Protocol,
			TCPPort:     t.TCPPort,
			ConnectedAt: t.ConnectedAt.Format(time.RFC3339),
			InFlight:    t.pendingCount.Load(),
			AllowedIPs:  t.AllowedIPs,
			DeniedIPs:   t.DeniedIPs,
			BasicAuth:   t.BasicAuth != "",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tunnels": out})
}

func (s *Server) handleAdminTunnelRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("id")
	tunnel := s.tunnels.LookupByID(id)
	if tunnel == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "tunnel not found"})
		return
	}
	subdomain := tunnel.Subdomain
	username := tunnel.Username
	// Force a graceful release: the client is being revoked by the operator,
	// not recovering from a network glitch, so no reconnect reservation.
	tunnel.graceful.Store(true)
	s.tunnels.Unregister(id)
	s.metrics.Inc("mabo_tunnels_revoked_total", "")
	s.logger.Info("tunnel revoked via admin API", "tunnel_id", id, "subdomain", subdomain, "username", username)
	writeJSON(w, http.StatusOK, map[string]any{"revoked": id})
}

func (s *Server) handleAdminUsersReload(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.ReloadUsers(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users_loaded": s.users.Count()})
}

func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":           version.Version,
		"domain":            s.config.Domain,
		"active_tunnels":    s.tunnels.ActiveCount(),
		"users_loaded":      s.users.Count(),
		"plaintext_entries": s.users.PlaintextEntries(),
		"uptime_seconds":    int64(time.Since(s.startedAt).Seconds()),
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.metrics.SetGauge("mabo_tunnels_active", int64(s.tunnels.ActiveCount()))
	s.metrics.SetGauge("mabo_users_loaded", int64(s.users.Count()))
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write([]byte(s.metrics.Render()))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
