package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/maborak/mabo-tunnel/internal/client"
	"github.com/maborak/mabo-tunnel/internal/config"
)

type portEntry struct {
	name          string
	host          string // forward target host (default: localhost)
	port          int
	auth          string // per-tunnel basic auth override from YAML
	headersAdd    map[string]string
	headersRemove []string
}

// defaultServerURL is where the client dials when neither --server nor
// MABO_TUNNEL_SERVER is set. It points at a local server on purpose: a binary built
// from this repo must never default to someone else's tunnel host. Override it
// for your own distribution with:
//
//	go build -ldflags "-X main.defaultServerURL=wss://tunnel.example.com" ./cmd/client
var defaultServerURL = "ws://localhost:8080"

func main() {
	serverURL := flag.String("server", envOrDefault("MABO_TUNNEL_SERVER", defaultServerURL), "Server WebSocket URL")
	token := flag.String("token", os.Getenv("MABO_TUNNEL_TOKEN"), "Auth token")
	subdomain := flag.String("subdomain", os.Getenv("MABO_TUNNEL_SUBDOMAIN"), "Request specific subdomain (single port only)")
	configFile := flag.String("config", "", "Path to YAML config file (default: mabo-tunnel.yml in current directory)")

	var portFlag string
	flag.StringVar(&portFlag, "port", "", "Ports to expose. Comma-separated, with optional name and host.\n  Examples: --port=3000  --port=ui:5173  --port=ui:192.168.0.40:5173,api:9001")

	tunnelProtocol := flag.String("protocol", envOrDefault("MABO_TUNNEL_PROTOCOL", "http"), "Tunnel protocol: \"http\" (default) or \"tcp\"")
	basicAuth := flag.String("auth", os.Getenv("MABO_TUNNEL_AUTH"), "HTTP Basic Auth for the tunnel (format: \"user:pass\")")

	var headerAddFlags multiFlag
	var headerRemoveFlags multiFlag
	flag.Var(&headerAddFlags, "header-add", "Add/override a header on proxied requests (e.g. \"X-Foo: bar\"). Can be repeated.")
	flag.Var(&headerRemoveFlags, "header-remove", "Remove a header from proxied requests (e.g. \"Cookie\"). Can be repeated.")
	flag.Parse()

	// Load config file if specified or if default exists.
	var fileCfg *config.FileConfig
	cfgPath := *configFile
	if cfgPath == "" {
		cfgPath = "mabo-tunnel.yml"
	}
	if *configFile != "" {
		// Explicit --config: error if file not found.
		cfg, err := config.Load(cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config %s: %v\n", cfgPath, err)
			os.Exit(1)
		}
		if cfg == nil {
			fmt.Fprintf(os.Stderr, "Error: config file %s not found\n", cfgPath)
			os.Exit(1)
		}
		fileCfg = cfg
	} else {
		// No --config flag: silently try default mabo-tunnel.yml.
		cfg, err := config.Load(cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: error loading %s: %v\n", cfgPath, err)
		}
		fileCfg = cfg // may be nil if file doesn't exist
	}

	// Merge: CLI flags take precedence over config file values.
	if fileCfg != nil {
		if *serverURL == defaultServerURL && fileCfg.Server != "" {
			*serverURL = fileCfg.Server
		}
		if *token == "" && fileCfg.Token != "" {
			*token = fileCfg.Token
		}
	}

	if *token == "" {
		fmt.Fprintln(os.Stderr, "Error: --token is required")
		flag.Usage()
		os.Exit(1)
	}

	// Parse CLI header flags into maps (apply to all CLI-defined tunnels).
	cliHeadersAdd := parseHeaderAddFlags(headerAddFlags)
	cliHeadersRemove := []string(headerRemoveFlags)

	// Build tunnel entries: CLI --port takes precedence; fall back to config tunnels.
	var entries []portEntry
	if portFlag != "" {
		entries = parsePortFlag(portFlag)
		// Apply CLI header flags to all CLI-defined tunnels.
		for i := range entries {
			entries[i].headersAdd = cliHeadersAdd
			entries[i].headersRemove = cliHeadersRemove
		}
	} else if fileCfg != nil && len(fileCfg.Tunnels) > 0 {
		for name, t := range fileCfg.Tunnels {
			e := portEntry{
				name: name,
				host: t.Host,
				port: t.Port,
				auth: t.Auth,
			}
			// Start with YAML-defined headers.
			if len(t.Headers.Add) > 0 {
				e.headersAdd = make(map[string]string, len(t.Headers.Add))
				for k, v := range t.Headers.Add {
					e.headersAdd[k] = v
				}
			}
			if len(t.Headers.Remove) > 0 {
				e.headersRemove = make([]string, len(t.Headers.Remove))
				copy(e.headersRemove, t.Headers.Remove)
			}
			// CLI header flags override/extend YAML headers.
			for k, v := range cliHeadersAdd {
				if e.headersAdd == nil {
					e.headersAdd = make(map[string]string)
				}
				e.headersAdd[k] = v
			}
			for _, h := range cliHeadersRemove {
				e.headersRemove = append(e.headersRemove, h)
			}
			entries = append(entries, e)
		}
	}

	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "Error: --port is required (or define tunnels in config file)")
		fmt.Fprintln(os.Stderr, "  Examples: --port=3000  --port=ui:5173  --port=ui:5173,api:9001")
		flag.Usage()
		os.Exit(1)
	}

	if len(entries) > 1 && *subdomain != "" {
		fmt.Fprintln(os.Stderr, "Error: --subdomain cannot be used with multiple ports (use named ports instead)")
		os.Exit(1)
	}

	// Create shared display and inspector.
	display := client.NewDisplay(len(entries))
	inspector := client.NewInspector()

	// Start local dashboard on a random available port, bound to loopback only.
	// The dashboard exposes captured request and response bodies; ":0" would
	// publish them to everything on the local network.
	dashboard := client.NewLocalDashboard(inspector)
	go func() {
		if err := dashboard.Start("127.0.0.1:0"); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Dashboard error: %v\n", err)
		}
	}()
	dashboard.WaitReady()

	// Silence Go's default logger — net/http prints "Unsolicited response" warnings
	// to stderr which corrupt the Bubble Tea alt screen.
	log.SetOutput(io.Discard)

	// Create Bubble Tea program with alt screen.
	p := tea.NewProgram(
		client.NewTUIModel(),
		tea.WithAltScreen(),
	)
	display.SetProgram(p)

	// Show dashboard URL in the TUI (must be in goroutine — program isn't running yet).
	if dashURL := dashboard.URL(); dashURL != "" {
		go display.SetDashboardURL(dashURL)
	}

	// Context for tunnel clients — canceled when TUI quits or SIGINT.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
		dashboard.Stop()
		p.Quit()
	}()

	// Start tunnel clients in background.
	var wg sync.WaitGroup
	for _, e := range entries {
		tunnelAuth := e.auth
		if tunnelAuth == "" {
			tunnelAuth = *basicAuth
		}
		cfg := client.Config{
			ServerURL:     *serverURL,
			Token:         *token,
			LocalHost:     e.host,
			LocalPort:     e.port,
			Name:          e.name,
			Protocol:      *tunnelProtocol,
			BasicAuth:     tunnelAuth,
			Subdomain:     *subdomain,
			HeadersAdd:    e.headersAdd,
			HeadersRemove: e.headersRemove,
		}

		wg.Add(1)
		go func(c client.Config) {
			defer wg.Done()
			cl := client.New(c, display, inspector, dashboard)
			if err := cl.Run(ctx); err != nil && ctx.Err() == nil {
				display.LogConnectionError(c.LocalPort, err.Error())
			}
		}(cfg)
	}

	// Run the TUI (blocks until quit).
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
	}

	// TUI exited — cancel tunnel clients and wait.
	cancel()
	wg.Wait()
}

// multiFlag allows a flag to be specified multiple times.
type multiFlag []string

func (f *multiFlag) String() string { return strings.Join(*f, ", ") }
func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

// parseHeaderAddFlags converts --header-add "Key: Value" flags into a map.
func parseHeaderAddFlags(flags []string) map[string]string {
	if len(flags) == 0 {
		return nil
	}
	m := make(map[string]string, len(flags))
	for _, f := range flags {
		parts := strings.SplitN(f, ":", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Warning: invalid --header-add %q (expected \"Key: Value\"), skipping\n", f)
			continue
		}
		m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return m
}

// parsePortFlag parses the --port value: comma-separated entries of "port",
// "name:port", or "name:host:port".
//
// Splitting is done from the right, because an IPv6 host is full of colons.
// Bracketed literals ("api:[::1]:9001") are unwrapped.
func parsePortFlag(flag string) []portEntry {
	var entries []portEntry
	for _, part := range strings.Split(flag, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// The port is always the trailing segment.
		idx := strings.LastIndex(part, ":")
		portStr := part
		rest := ""
		if idx != -1 {
			portStr = part[idx+1:]
			rest = part[:idx]
		}

		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			fmt.Fprintf(os.Stderr, "Warning: invalid port %q in %q, skipping\n", portStr, part)
			continue
		}

		switch {
		case rest == "":
			// "3000"
			entries = append(entries, portEntry{port: port})
		default:
			// "name:port" or "name:host:port" — the name is the first segment,
			// anything after it is the host.
			name, host := rest, ""
			if i := strings.Index(rest, ":"); i != -1 {
				name, host = rest[:i], strings.Trim(rest[i+1:], "[]")
			}
			if name == "" {
				fmt.Fprintf(os.Stderr, "Warning: invalid port entry %q, skipping\n", part)
				continue
			}
			entries = append(entries, portEntry{name: name, host: host, port: port})
		}
	}
	return entries
}

func envOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
