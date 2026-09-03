package client

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/maborak/mabo-tunnel/internal/version"
)

// LocalTunnelInfo holds info about a locally-running tunnel for the dashboard.
type LocalTunnelInfo struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	LocalPort int       `json:"local_port"`
	Name      string    `json:"name"`
	StartedAt time.Time `json:"started_at"`
}

// LocalDashboard runs on localhost and serves the inspection dashboard + API.
type LocalDashboard struct {
	inspector  *Inspector
	mu         sync.RWMutex
	tunnels    []LocalTunnelInfo
	startTime  time.Time
	server     *http.Server
	actualAddr string
	ready      chan struct{}
}

// NewLocalDashboard creates a new local dashboard.
func NewLocalDashboard(inspector *Inspector) *LocalDashboard {
	return &LocalDashboard{
		inspector: inspector,
		startTime: time.Now(),
		ready:     make(chan struct{}),
	}
}

// AddTunnel registers a tunnel for display in the dashboard.
//
// The server assigns a fresh tunnel ID per connection, so a reconnecting
// client calls this repeatedly for the same configured tunnel. Keying on
// (name, local port) reuses the entry — and migrates the inspector's captured
// history to the new ID — instead of growing one sidebar entry (and one
// unreachable ring buffer) per reconnect.
func (ld *LocalDashboard) AddTunnel(id, url string, localPort int, name string) {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	for i := range ld.tunnels {
		if ld.tunnels[i].LocalPort == localPort && ld.tunnels[i].Name == name {
			if ld.inspector != nil {
				ld.inspector.ReassignTunnel(ld.tunnels[i].ID, id)
			}
			ld.tunnels[i].ID = id
			ld.tunnels[i].URL = url
			ld.tunnels[i].StartedAt = time.Now()
			return
		}
	}
	ld.tunnels = append(ld.tunnels, LocalTunnelInfo{
		ID:        id,
		URL:       url,
		LocalPort: localPort,
		Name:      name,
		StartedAt: time.Now(),
	})
}

// Start starts the local dashboard HTTP server on the given address.
// Use ":0" to bind to a random available port.
func (ld *LocalDashboard) Start(addr string) error {
	mux := http.NewServeMux()

	// Dashboard UI
	dashboard := NewDashboardHandler()
	dashboard.RegisterRoutes(mux)

	// API routes
	mux.HandleFunc("/_api/tunnels", localOnly(ld.handleTunnels))
	mux.HandleFunc("/_api/tunnels/", localOnly(ld.handleTunnelRoutes))
	mux.HandleFunc("/_api/status", localOnly(ld.handleStatus))

	// Redirect root to dashboard
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/_dashboard/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		close(ld.ready)
		return err
	}

	port := ln.Addr().(*net.TCPAddr).Port
	ld.mu.Lock()
	ld.actualAddr = fmt.Sprintf("http://localhost:%d", port)
	ld.mu.Unlock()
	close(ld.ready)

	ld.server = &http.Server{Handler: mux}
	return ld.server.Serve(ln)
}

// WaitReady blocks until the dashboard has bound its port (or failed).
func (ld *LocalDashboard) WaitReady() {
	<-ld.ready
}

// URL returns the full dashboard URL (e.g. "http://localhost:12345").
// Only valid after WaitReady returns.
func (ld *LocalDashboard) URL() string {
	ld.mu.RLock()
	defer ld.mu.RUnlock()
	return ld.actualAddr
}

// Stop shuts down the dashboard server.
func (ld *LocalDashboard) Stop() {
	if ld.server != nil {
		ld.server.Close()
	}
}

func (ld *LocalDashboard) handleTunnels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ld.mu.RLock()
	tunnels := make([]map[string]any, 0, len(ld.tunnels))
	for _, t := range ld.tunnels {
		tunnels = append(tunnels, map[string]any{
			"id":            t.ID,
			"subdomain":     t.URL,
			"username":      t.Name,
			"plan":          "local",
			"connected_at":  t.StartedAt,
			"request_count": ld.inspector.RequestCount(t.ID),
		})
	}
	ld.mu.RUnlock()

	jsonResponse(w, tunnels, http.StatusOK)
}

func (ld *LocalDashboard) handleTunnelRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/_api/tunnels/")
	parts := strings.SplitN(path, "/", 4)

	if len(parts) == 0 || parts[0] == "" {
		jsonError(w, "tunnel ID required", http.StatusBadRequest)
		return
	}

	tunnelID := parts[0]

	if len(parts) == 1 && r.Method == http.MethodGet {
		ld.mu.RLock()
		var found *LocalTunnelInfo
		for i := range ld.tunnels {
			if ld.tunnels[i].ID == tunnelID {
				found = &ld.tunnels[i]
				break
			}
		}
		ld.mu.RUnlock()
		if found == nil {
			jsonError(w, "tunnel not found", http.StatusNotFound)
			return
		}
		jsonResponse(w, found, http.StatusOK)
		return
	}

	if len(parts) >= 2 && parts[1] == "har" {
		if len(parts) == 2 && r.Method == http.MethodGet {
			requests := ld.inspector.GetRequests(tunnelID)
			if requests == nil {
				requests = make([]*CapturedRequest, 0)
			}
			har := BuildHAR(requests, version.Version)
			if r.URL.Query().Get("download") != "" {
				w.Header().Set("Content-Disposition", `attachment; filename="mabo-tunnel-`+tunnelID+`.har"`)
			}
			jsonResponse(w, har, http.StatusOK)
			return
		}
	}

	if len(parts) >= 2 && parts[1] == "requests" {
		if len(parts) == 2 && r.Method == http.MethodGet {
			requests := ld.inspector.GetRequests(tunnelID)
			if requests == nil {
				requests = make([]*CapturedRequest, 0)
			}
			type summary struct {
				ID             string    `json:"id"`
				Method         string    `json:"method"`
				Path           string    `json:"path"`
				ResponseStatus int       `json:"response_status"`
				DurationMs     float64   `json:"duration_ms"`
				Timestamp      time.Time `json:"timestamp"`
			}
			summaries := make([]summary, 0, len(requests))
			for _, req := range requests {
				summaries = append(summaries, summary{
					ID:             req.ID,
					Method:         req.Method,
					Path:           req.Path,
					ResponseStatus: req.ResponseStatus,
					DurationMs:     req.DurationMs,
					Timestamp:      req.Timestamp,
				})
			}
			jsonResponse(w, summaries, http.StatusOK)
			return
		}

		if len(parts) == 3 && r.Method == http.MethodGet {
			req := ld.inspector.GetRequest(tunnelID, parts[2])
			if req == nil {
				jsonError(w, "request not found", http.StatusNotFound)
				return
			}
			jsonResponse(w, req, http.StatusOK)
			return
		}

		// POST /_api/tunnels/:id/requests/:rid/replay
		if len(parts) == 4 && parts[3] == "replay" && r.Method == http.MethodPost {
			if !requireLocalRequest(r) {
				jsonError(w, "replay requires the dashboard UI", http.StatusForbidden)
				return
			}
			captured := ld.inspector.GetRequest(tunnelID, parts[2])
			if captured == nil {
				jsonError(w, "request not found", http.StatusNotFound)
				return
			}

			// Find the tunnel URL to replay against.
			ld.mu.RLock()
			var tunnelURL string
			for _, t := range ld.tunnels {
				if t.ID == tunnelID {
					tunnelURL = t.URL
					break
				}
			}
			ld.mu.RUnlock()

			if tunnelURL == "" {
				jsonError(w, "tunnel not found", http.StatusNotFound)
				return
			}

			// Replay the request through the tunnel.
			replayURL := tunnelURL + captured.Path
			client := &http.Client{Timeout: 30 * time.Second}
			req, err := http.NewRequest(captured.Method, replayURL, nil)
			if err != nil {
				jsonError(w, "failed to create request: "+err.Error(), http.StatusInternalServerError)
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				jsonError(w, "replay failed: "+err.Error(), http.StatusBadGateway)
				return
			}
			resp.Body.Close()

			jsonResponse(w, map[string]any{
				"status":     "replayed",
				"request_id": parts[2],
				"method":     captured.Method,
				"path":       captured.Path,
				"response":   resp.StatusCode,
			}, http.StatusOK)
			return
		}
	}

	jsonError(w, "not found", http.StatusNotFound)
}

func (ld *LocalDashboard) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ld.mu.RLock()
	tunnelCount := len(ld.tunnels)
	ld.mu.RUnlock()

	uptime := time.Since(ld.startTime)
	jsonResponse(w, map[string]any{
		"active_tunnels": tunnelCount,
		"uptime":         uptime.Round(time.Second).String(),
		"uptime_seconds": uptime.Seconds(),
		"started_at":     ld.startTime,
		"version":        version.Version,
	}, http.StatusOK)
}

// jsonResponse writes a JSON body.
//
// There is deliberately no Access-Control-Allow-Origin header. The dashboard is
// same-origin with this API, and a wildcard would let any page the user happens
// to visit read captured request and response bodies — cookies, bearer tokens,
// and payloads belonging to whatever is being tunneled.
func jsonResponse(w http.ResponseWriter, data any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// localOnly rejects requests that did not arrive at a loopback name.
//
// The listener is already bound to 127.0.0.1, but a hostname that resolves to
// loopback lets a remote page reach it through the browser (DNS rebinding).
// Checking the Host header closes that: an attacker controls the name, not what
// the browser sends as Host.
func localOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		switch host {
		case "localhost", "127.0.0.1", "::1", "":
			next(w, r)
		default:
			jsonError(w, "dashboard is only reachable at localhost", http.StatusForbidden)
		}
	}
}

// requireLocalRequest guards state-changing endpoints against cross-site
// requests. A cross-origin fetch cannot set X-Mabo Tunnel-Dashboard without
// triggering a preflight, and we answer no preflight, so only the dashboard's
// own scripts can reach these.
func requireLocalRequest(r *http.Request) bool {
	return r.Header.Get("X-Mabo Tunnel-Dashboard") != ""
}
