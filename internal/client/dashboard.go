package client

import (
	_ "embed"
	"net/http"
)

//go:embed dashboard.html
var dashboardHTML []byte

// DashboardHandler serves the embedded web inspection dashboard.
type DashboardHandler struct{}

// NewDashboardHandler creates a new DashboardHandler.
func NewDashboardHandler() *DashboardHandler {
	return &DashboardHandler{}
}

// RegisterRoutes registers dashboard routes on the given mux.
func (d *DashboardHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/_dashboard/", d.serveDashboard)
}

func (d *DashboardHandler) serveDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(dashboardHTML)
}
