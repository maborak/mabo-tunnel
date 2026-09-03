package client

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Port colors for multi-tunnel coloring — the single source of truth for both
// the lipgloss header rendering and the raw ANSI codes used in log lines.
var portColorCodes = []string{
	"42",  // green
	"45",  // cyan
	"214", // yellow/orange
	"206", // magenta/pink
	"75",  // blue
	"252", // white
}

func portColor(i int) lipgloss.Color {
	return lipgloss.Color(portColorCodes[i%len(portColorCodes)])
}

func ansiColor(code string) string {
	return "\033[38;5;" + code + "m"
}

// ANSI for inline log coloring (used in log line strings).
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
)

// ── Messages sent to the TUI ────────────────────────────────

// MsgTunnelReady signals a tunnel has connected.
type MsgTunnelReady struct {
	URL       string
	LocalAddr string
	LocalPort int
	Name      string
}

// MsgRequest logs a proxied request.
type MsgRequest struct {
	Color     string
	LocalPort int
	Method    string
	Path      string
	Status    int
	Duration  time.Duration
}

// MsgError logs an error for a tunnel.
type MsgError struct {
	Color     string
	LocalPort int
	Method    string
	Path      string
	Error     string
}

// MsgConnError logs a connection-level error.
type MsgConnError struct {
	LocalPort int
	Error     string
}

// MsgPing updates the ping value.
type MsgPing struct {
	Ms int64
}

// MsgUsername updates the username.
type MsgUsername struct {
	Username string
}

// MsgDashboardURL updates the dashboard URL in the TUI.
type MsgDashboardURL struct {
	URL string
}

// ── TunnelInfo ──────────────────────────────────────────────

// TunnelInfo holds display info for one tunnel.
type TunnelInfo struct {
	URL       string
	LocalAddr string // "host:port" target
	LocalPort int
	Name      string
	Color     lipgloss.Color
}

// ── Model ───────────────────────────────────────────────────

// TUIModel is the Bubble Tea model for the client display.
type TUIModel struct {
	viewport     viewport.Model
	logs         []string
	tunnels      []TunnelInfo
	tunnelIndex  map[string]int // tunnelKey → index in tunnels slice
	username     string
	ping         string
	dashboardURL string
	width        int
	height       int
	ready        bool
}

// NewTUIModel creates the initial model.
func NewTUIModel() TUIModel {
	return TUIModel{
		tunnelIndex: make(map[string]int),
		username:    "connecting...",
		ping:        "--",
	}
}

func (m TUIModel) Init() tea.Cmd {
	return nil
}

func (m TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		vpHeight := msg.Height - m.headerHeight()
		if vpHeight < 1 {
			vpHeight = 1
		}

		if !m.ready {
			m.viewport = viewport.New(msg.Width, vpHeight)
			m.viewport.SetContent(m.renderLogs())
			m.ready = true
		} else {
			m.viewport.Width = msg.Width
			m.viewport.Height = vpHeight
		}

	case MsgTunnelReady:
		// De-duplicate on reconnect using a map for O(1) lookup.
		key := tunnelKey(msg.Name, msg.LocalAddr, msg.LocalPort)
		if idx, ok := m.tunnelIndex[key]; ok && idx < len(m.tunnels) {
			m.tunnels[idx].URL = msg.URL
			m.tunnels[idx].LocalAddr = msg.LocalAddr
			m.tunnels[idx].LocalPort = msg.LocalPort
			m.tunnels[idx].Name = msg.Name
		} else {
			color := portColor(len(m.tunnels))
			m.tunnelIndex[key] = len(m.tunnels)
			m.tunnels = append(m.tunnels, TunnelInfo{
				URL:       msg.URL,
				LocalAddr: msg.LocalAddr,
				LocalPort: msg.LocalPort,
				Name:      msg.Name,
				Color:     color,
			})
		}
		if m.ready {
			vpH := m.height - m.headerHeight()
			if vpH < 1 {
				vpH = 1
			}
			m.viewport.Height = vpH
		}

	case MsgUsername:
		m.username = msg.Username

	case MsgDashboardURL:
		m.dashboardURL = msg.URL
		if m.ready {
			vpH := m.height - m.headerHeight()
			if vpH < 1 {
				vpH = 1
			}
			m.viewport.Height = vpH
		}

	case MsgPing:
		m.ping = fmt.Sprintf("%dms", msg.Ms)

	case MsgRequest:
		line := m.formatRequest(msg)
		m.appendLog(line)

	case MsgError:
		line := m.formatError(msg)
		m.appendLog(line)

	case MsgConnError:
		ts := time.Now().Format("15:04:05")
		line := fmt.Sprintf("%s%s%s %s%s[:%d] %s%s",
			ansiDim, ts, ansiReset,
			ansiRed, ansiBold, msg.LocalPort, msg.Error, ansiReset)
		m.appendLog(line)
	}

	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

func (m TUIModel) View() string {
	if !m.ready {
		return "  Connecting..."
	}
	return m.renderHeader() + m.viewport.View()
}

// ── Header rendering ────────────────────────────────────────

var (
	headerStyle = lipgloss.NewStyle().
			PaddingLeft(2).
			PaddingTop(1)

	labelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("252"))

	valueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240"))

	separatorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("238")).
			PaddingLeft(2)
)

func (m TUIModel) renderHeader() string {
	var b strings.Builder

	// Username + Ping line
	b.WriteString(headerStyle.Render(
		labelStyle.Render("Username: ") + valueStyle.Render(m.username) +
			"    " +
			labelStyle.Render("Ping: ") + valueStyle.Render(m.ping),
	))
	b.WriteString("\n")

	// Subdomains label
	b.WriteString(headerStyle.Render(labelStyle.Render("Subdomains:")))
	b.WriteString("\n")

	// Each tunnel
	for _, t := range m.tunnels {
		arrow := lipgloss.NewStyle().Foreground(t.Color).Render("▸")
		target := t.LocalAddr
		if target == "" {
			target = fmt.Sprintf("localhost:%d", t.LocalPort)
		}
		local := dimStyle.Render(fmt.Sprintf("→ http://%s", target))

		// Derive both http and https URLs from the tunnel URL.
		httpURL, httpsURL := t.URL, t.URL
		if strings.HasPrefix(t.URL, "http://") {
			httpsURL = "https://" + strings.TrimPrefix(t.URL, "http://")
		} else if strings.HasPrefix(t.URL, "https://") {
			httpURL = "http://" + strings.TrimPrefix(t.URL, "https://")
		}

		httpsRendered := lipgloss.NewStyle().Foreground(t.Color).Bold(true).Render(httpsURL)
		httpRendered := lipgloss.NewStyle().Foreground(t.Color).Bold(true).Render(httpURL)
		b.WriteString(fmt.Sprintf("      %s %s %s\n", arrow, httpsRendered, local))
		b.WriteString(fmt.Sprintf("      %s %s\n", arrow, httpRendered))
	}

	// Dashboard URL
	if m.dashboardURL != "" {
		b.WriteString("\n")
		b.WriteString(headerStyle.Render(
			labelStyle.Render("Dashboard: ") +
				lipgloss.NewStyle().Foreground(lipgloss.Color("45")).Bold(true).Render(m.dashboardURL),
		))
		b.WriteString("\n")
	}

	// Separator
	w := m.width
	if w < 60 {
		w = 60
	}
	b.WriteString("\n")
	b.WriteString(separatorStyle.Render(strings.Repeat("─", w-4)))
	b.WriteString("\n\n")

	return b.String()
}

func (m TUIModel) headerHeight() int {
	return strings.Count(m.renderHeader(), "\n")
}

// ── Log formatting ──────────────────────────────────────────

func (m TUIModel) formatRequest(msg MsgRequest) string {
	ts := time.Now().Format("15:04:05")

	statusColor := ansiGreen
	if msg.Status >= 400 && msg.Status < 500 {
		statusColor = ansiYellow
	} else if msg.Status >= 500 || msg.Status == 0 {
		statusColor = ansiRed
	}

	return fmt.Sprintf("%s%s%s %s%-7s%s %s%-4s%s %-35s %s%d%s  %s%s%s",
		ansiDim, ts, ansiReset,
		msg.Color, fmt.Sprintf(":%d", msg.LocalPort), ansiReset,
		msg.Color, msg.Method, ansiReset,
		truncatePath(msg.Path, 35),
		statusColor, msg.Status, ansiReset,
		ansiDim, formatDuration(msg.Duration), ansiReset,
	)
}

func (m TUIModel) formatError(msg MsgError) string {
	ts := time.Now().Format("15:04:05")

	return fmt.Sprintf("%s%s%s %s%-7s%s %s%-4s%s %-35s %s%sERR%s  %s%s%s",
		ansiDim, ts, ansiReset,
		msg.Color, fmt.Sprintf(":%d", msg.LocalPort), ansiReset,
		msg.Color, msg.Method, ansiReset,
		truncatePath(msg.Path, 35),
		ansiRed, ansiBold, ansiReset,
		ansiRed, truncatePath(msg.Error, 40), ansiReset,
	)
}

// maxLogLines caps the scrollback. Without a cap the slice grows for the life
// of the session and every redraw re-joins the whole history.
const maxLogLines = 1000

func (m *TUIModel) appendLog(line string) {
	m.logs = append(m.logs, line)
	if len(m.logs) > maxLogLines {
		// Drop the oldest lines. Copying into the front reuses the backing
		// array, so this does not reallocate on every request.
		excess := len(m.logs) - maxLogLines
		copy(m.logs, m.logs[excess:])
		m.logs = m.logs[:maxLogLines]
	}
	if m.ready {
		follow := m.viewport.AtBottom()
		m.viewport.SetContent(m.renderLogs())
		if follow {
			m.viewport.GotoBottom()
		}
	}
}

// renderLogs joins the scrollback into the viewport's content. Bounded by
// maxLogLines, so its cost does not grow with session length.
func (m *TUIModel) renderLogs() string {
	var b strings.Builder
	// One allocation for the whole join: assume a typical log line width.
	b.Grow(len(m.logs) * 96)
	for i, line := range m.logs {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(line)
	}
	return b.String()
}

// ── Display adapter ─────────────────────────────────────────

// tunnelKey returns a stable identity for a tunnel so reconnects can be
// matched to their original entry. Prefer the user-supplied name; fall back
// to localAddr:localPort for unnamed tunnels.
func tunnelKey(name, localAddr string, localPort int) string {
	if name != "" {
		return "name:" + name
	}
	return fmt.Sprintf("addr:%s:%d", localAddr, localPort)
}

// Display bridges between Client goroutines and the Bubble Tea TUI.
// Clients call Display methods; Display sends messages to the tea.Program.
type Display struct {
	program *tea.Program
	mu      sync.Mutex
	count   int
	// colorsByKey remembers which color was handed out for each tunnel key,
	// so reconnects keep their original color instead of consuming a new slot.
	colorsByKey map[string]string
}

// NewDisplay creates a Display. Call SetProgram after tea.NewProgram.
func NewDisplay() *Display {
	return &Display{
		colorsByKey: make(map[string]string),
	}
}

// SetProgram wires the display to the running Bubble Tea program.
func (d *Display) SetProgram(p *tea.Program) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.program = p
}

func (d *Display) send(msg tea.Msg) {
	d.mu.Lock()
	p := d.program
	d.mu.Unlock()
	if p != nil {
		p.Send(msg)
	}
}

func (d *Display) SetUsername(username string) {
	d.send(MsgUsername{Username: username})
}

func (d *Display) SetDashboardURL(url string) {
	d.send(MsgDashboardURL{URL: url})
}

func (d *Display) AddTunnel(url string, localPort int, name string, localAddr string) string {
	d.send(MsgTunnelReady{URL: url, LocalAddr: localAddr, LocalPort: localPort, Name: name})

	key := tunnelKey(name, localAddr, localPort)

	d.mu.Lock()
	defer d.mu.Unlock()
	if existing, ok := d.colorsByKey[key]; ok {
		return existing
	}
	color := ansiColor(portColorCodes[d.count%len(portColorCodes)])
	d.count++
	d.colorsByKey[key] = color
	return color
}

func (d *Display) UpdatePing(ms int64) {
	d.send(MsgPing{Ms: ms})
}

func (d *Display) LogRequest(color string, localPort int, method, path string, status int, duration time.Duration) {
	d.send(MsgRequest{Color: color, LocalPort: localPort, Method: method, Path: path, Status: status, Duration: duration})
}

func (d *Display) LogError(color string, localPort int, method, path, errMsg string) {
	d.send(MsgError{Color: color, LocalPort: localPort, Method: method, Path: path, Error: errMsg})
}

func (d *Display) LogConnectionError(localPort int, msg string) {
	d.send(MsgConnError{LocalPort: localPort, Error: msg})
}

// ── Helpers ─────────────────────────────────────────────────

func truncatePath(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	cut := maxLen - 3
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
