package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/libdns/digitalocean"
	"github.com/libdns/libdns"
	"github.com/libdns/route53"
	"github.com/maborak/mabo-tunnel/internal/auth"
	"github.com/maborak/mabo-tunnel/internal/protocol"
	"github.com/maborak/mabo-tunnel/internal/version"

	"github.com/gorilla/websocket"
)

const (
	// WebSocket keepalive interval.
	pingInterval = 25 * time.Second
	// How long to wait for a pong before considering the connection dead.
	pongWait = 90 * time.Second
	// Max inbound WebSocket frame size (16 MB).
	maxMessageSize = 16 * 1024 * 1024
	// Max concurrent proxied requests per tunnel.
	maxProxiedPerTunnel = 200
	// WebSocket read/write buffer size. Large enough that a 32 KiB body chunk
	// leaves in one or two socket writes instead of eleven.
	wsBufferSize = 64 * 1024
)

// Config holds server configuration.
type Config struct {
	Addr          string
	Domain        string
	ControlDomain string
	UsersFile     string
	TCPPortMin    int // start of TCP port range for TCP tunnels (inclusive)
	TCPPortMax    int // end of TCP port range for TCP tunnels (inclusive)

	// TrustedProxies lists CIDRs whose X-Forwarded-For header is believed.
	// Empty means loopback plus the private ranges.
	TrustedProxies []string

	// LogLevel is "debug", "info", "warn", or "error". Empty means info.
	LogLevel string

	// Keepalive tuning. Zero uses the defaults below. These exist so tests can
	// exercise ping/pong and idle timeout behavior in seconds rather than
	// sleeping through the production cadence.
	KeepaliveInterval time.Duration // ping cadence, default 25s
	KeepaliveTimeout  time.Duration // pong deadline, default 90s

	// Auth rate limiting. Zero uses the defaults: 5 attempts per minute.
	RateLimitMax    int
	RateLimitWindow time.Duration

	// Per-plan concurrent-tunnel quotas. Zero uses the built-in defaults
	// (free=1, pro=10); individual users may override theirs with the optional
	// max-tunnels field in the users file.
	PlanFreeLimit int
	PlanProLimit  int

	// Per-tunnel public request-rate cap. TunnelRateRPS <= 0 (the default)
	// disables edge rate limiting.
	TunnelRateRPS   int
	TunnelRateBurst int

	// UpstreamHeaderTimeout bounds how long a proxied request waits for the
	// local server's response headers. Once headers arrive there is no further
	// deadline, so a stream may run for as long as it needs. Zero means 60s.
	UpstreamHeaderTimeout time.Duration

	// AIO (all-in-one) mode: built-in HTTP + HTTPS + auto certs.
	AIO          bool
	AIOBind      string // bind IP (default: 0.0.0.0)
	AIOHTTPPort  int    // HTTP port for AIO mode (default: 80)
	AIOHTTPSPort int    // HTTPS port for AIO mode (default: 443)
	AIOEmail     string // ACME email for Let's Encrypt
	AIOCFToken   string // Cloudflare API token for DNS-01 challenge
	AIOCertPath  string // certificate storage directory

	// AIODNSProvider selects the DNS-01 challenge provider: "cloudflare"
	// (default), "digitalocean", or "route53". AIODNSExtra carries the
	// provider-specific second credential — the AWS Secret Access Key for
	// route53 (AIODNSecret holds the Access Key ID), unused otherwise.
	AIODNSProvider string
	AIODNSSecret   string

	// EmbeddedUsers holds users data decrypted at startup (same format as users.txt).
	// If non-empty, takes precedence over UsersFile.
	EmbeddedUsers string

	// AdminToken enables the admin API (/admin/*, /metrics) when non-empty.
	// Requests must present it as "Authorization: Bearer <token>" or
	// "X-Admin-Token: <token>". Empty disables both endpoints entirely.
	AdminToken string

	// CustomDomains lists the zone suffixes under which clients may register
	// their own verified hostnames (e.g. "apps.example.com" lets a user claim
	// wilmer.apps.example.com after proving control via a TXT record). Empty
	// disables custom domains.
	CustomDomains []string
}

// Server is the main Mabo Tunnel server.
type Server struct {
	config    Config
	tunnels   *TunnelManager
	users     *auth.UserStore
	limiter   *auth.RateLimiter
	proxy     *ProxyHandler
	logger    *slog.Logger
	mux       *http.ServeMux
	upgrader  websocket.Upgrader
	metrics   *Metrics
	startedAt time.Time

	// dnsReader is the ACME DNS provider's record reader, set in AIO mode and
	// used to verify custom-domain ownership via TXT lookup. Nil in plain mode.
	dnsReader libdns.RecordGetter

	// Resolved keepalive timings.
	pingInterval time.Duration
	pongWait     time.Duration
}

// parseLogLevel maps a config string onto a slog level.
func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// logPlaintextWarning flags a users store that still holds unhashed tokens:
// the file (and any binary embedding it) is then a credential list.
func logPlaintextWarning(logger *slog.Logger, users *auth.UserStore) {
	if n := users.PlaintextEntries(); n > 0 {
		logger.Warn("user file contains unhashed tokens — anyone who reads it can authenticate as those users",
			"plaintext_entries", n,
			"migrate_with", "mabo-tunnel-token migrate <users-file>",
		)
	}
}

// New creates a new Server instance.
func New(cfg Config) (*Server, error) {
	level := parseLogLevel(cfg.LogLevel)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
		// Source resolution costs a runtime.Caller on every record. Keep it
		// for debug runs, where the volume is intentional, not for production
		// where it sits on the per-request path.
		AddSource: level == slog.LevelDebug,
	}))

	var users *auth.UserStore
	var err error
	if cfg.EmbeddedUsers != "" {
		users, err = auth.NewUserStoreFromData(cfg.EmbeddedUsers)
		if err != nil {
			return nil, fmt.Errorf("parse embedded users: %w", err)
		}
		logger.Info("loaded embedded users", "count", users.Count())
	} else {
		users, err = auth.NewUserStore(cfg.UsersFile)
		if err != nil {
			return nil, fmt.Errorf("load users: %w", err)
		}
		logger.Info("loaded users", "count", users.Count(), "file", cfg.UsersFile)
	}

	// A plaintext entry means the user file (and any binary embedding it) still
	// holds a usable credential. Hashed entries do not.
	logPlaintextWarning(logger, users)

	rateMax := cfg.RateLimitMax
	if rateMax == 0 {
		rateMax = 5
	}
	rateWindow := cfg.RateLimitWindow
	if rateWindow == 0 {
		rateWindow = time.Minute
	}
	limiter := auth.NewRateLimiter(rateMax, rateWindow)

	tcpMin := cfg.TCPPortMin
	tcpMax := cfg.TCPPortMax
	if tcpMin == 0 {
		tcpMin = 10000
	}
	if tcpMax == 0 {
		tcpMax = 10100
	}
	tunnels := NewTunnelManager(cfg.Domain, tcpMin, tcpMax, logger)
	if cfg.PlanFreeLimit > 0 || cfg.PlanProLimit > 0 {
		tunnels.SetPlanLimits(cfg.PlanFreeLimit, cfg.PlanProLimit)
	}
	if cfg.TunnelRateRPS > 0 {
		tunnels.SetRateLimit(cfg.TunnelRateRPS, cfg.TunnelRateBurst)
	}
	metrics := NewMetrics()
	metrics.Gauge("mabo_tunnels_active", "Currently registered tunnels.")
	metrics.Gauge("mabo_users_loaded", "Users currently loaded from the users file.")
	metrics.Counter("mabo_tunnels_registered_total", "Tunnels registered since start.", "")
	metrics.Counter("mabo_tunnels_revoked_total", "Tunnels revoked via the admin API.", "")
	metrics.Counter("mabo_auth_attempts_total", "Tunnel auth handshakes attempted.", "")
	metrics.Counter("mabo_auth_failures_total", "Tunnel auth handshakes rejected.", "")
	metrics.Counter("mabo_http_requests_total", "Public HTTP requests entering the proxy.", "")
	metrics.Counter("mabo_http_responses_total", "Proxied responses by status class.", "status")
	proxy := NewProxyHandler(tunnels, cfg.Domain, cfg.TrustedProxies, cfg.UpstreamHeaderTimeout, logger)
	proxy.SetMetrics(metrics)

	pingEvery := cfg.KeepaliveInterval
	if pingEvery == 0 {
		pingEvery = pingInterval
	}
	pongDeadline := cfg.KeepaliveTimeout
	if pongDeadline == 0 {
		pongDeadline = pongWait
	}

	s := &Server{
		config:       cfg,
		tunnels:      tunnels,
		users:        users,
		limiter:      limiter,
		proxy:        proxy,
		logger:       logger,
		metrics:      metrics,
		startedAt:    time.Now(),
		pingInterval: pingEvery,
		pongWait:     pongDeadline,
		mux:          http.NewServeMux(),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  wsBufferSize,
			WriteBufferSize: wsBufferSize,
			CheckOrigin:     func(r *http.Request) bool { return true },
			// permessage-deflate. Tunneled payloads are mostly text (HTML,
			// JSON, SSE) and the client's uplink is usually the bottleneck.
			EnableCompression: true,
		},
	}

	s.mux.HandleFunc("/tunnel/connect", s.handleTunnelConnect)
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/ready", s.handleReady)
	s.mux.HandleFunc("GET /admin/tunnels", s.handleAdminTunnels)
	s.mux.HandleFunc("DELETE /admin/tunnels/{id}", s.handleAdminTunnelRevoke)
	s.mux.HandleFunc("POST /admin/users/reload", s.handleAdminUsersReload)
	s.mux.HandleFunc("GET /admin/stats", s.handleAdminStats)
	s.mux.HandleFunc("GET /metrics", s.handleMetrics)
	s.mux.HandleFunc("/", s.handleRoot)

	// Dashboard and API are served locally on the CLIENT side (localhost:4040).

	return s, nil
}

// effectiveScheme reports the scheme public tunnel URLs are advertised with.
// Only AIO mode terminates TLS itself; a plain-mode server sits behind a
// reverse proxy (see docs/deployment.md) and its URLs are honest about that.
func (s *Server) effectiveScheme() string {
	if s.config.AIO {
		return "https"
	}
	return "http"
}

// newHTTPServer builds an http.Server with timeouts suited to a tunnel edge.
//
// There is deliberately no WriteTimeout: a proxied response may legitimately
// stream for many minutes (SSE, LLM generation, large downloads), and
// WriteTimeout would cut it off mid-body regardless of activity. Time-to-first
// -byte is bounded per request in streamResponse instead. ReadHeaderTimeout
// bounds slowloris without capping upload duration.
func (s *Server) newHTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// Run starts the server and blocks until the context is canceled.
func (s *Server) Run(ctx context.Context) error {
	go s.watchUsers(ctx)
	if s.config.AIO {
		return s.runAIO(ctx)
	}
	return s.runPlain(ctx)
}

// ReloadUsers re-reads the users file and swaps the in-memory store. A parse
// failure keeps the previously loaded users: a half-edited file must not lock
// every token out. Embedded (AIO) stores are immutable by design.
func (s *Server) ReloadUsers() error {
	if s.config.EmbeddedUsers != "" {
		return fmt.Errorf("users are embedded in this binary; rebuild to change them")
	}
	if err := s.users.Reload(); err != nil {
		s.logger.Error("users reload failed; keeping previous users",
			"error", err,
			"file", s.config.UsersFile,
		)
		return err
	}
	s.logger.Info("users reloaded", "count", s.users.Count(), "file", s.config.UsersFile)
	logPlaintextWarning(s.logger, s.users)
	return nil
}

// usersWatchInterval is how often the users file's mtime/size is checked.
// Polling stays cheap and dependency-free; sub-second pickup is not a goal.
const usersWatchInterval = 5 * time.Second

// watchUsers reloads the users file when it changes on disk, so adding or
// revoking a user no longer requires a restart. Only file-backed stores are
// watched.
func (s *Server) watchUsers(ctx context.Context) {
	if s.config.EmbeddedUsers != "" {
		return
	}
	type fileStamp struct {
		modTime time.Time
		size    int64
	}
	stamp := func() fileStamp {
		st, err := os.Stat(s.config.UsersFile)
		if err != nil {
			return fileStamp{}
		}
		return fileStamp{modTime: st.ModTime(), size: st.Size()}
	}
	last := stamp()

	ticker := time.NewTicker(usersWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cur := stamp()
			if cur == last {
				continue
			}
			last = cur
			// A swap-in progress can briefly produce an empty file; a reload
			// that parses zero users is more likely an editor artifact than
			// an intent, so skip it and pick up the real content next tick.
			if cur.size == 0 {
				s.logger.Warn("users file is empty; waiting for content", "file", s.config.UsersFile)
				continue
			}
			_ = s.ReloadUsers()
		}
	}
}

// shutdown tears down shared background workers.
func (s *Server) shutdown() {
	s.tunnels.DrainAll()
	s.tunnels.Stop()
	s.limiter.Stop()
}

// Close releases a Server's background workers. Run does this itself on
// shutdown; Close is for callers that mount the Server as an http.Handler
// without ever calling Run, which is how the tests drive it.
func (s *Server) Close() {
	s.shutdown()
}

// runPlain starts the plain HTTP server (original behavior, for use behind a reverse proxy).
func (s *Server) runPlain(ctx context.Context) error {
	httpServer := s.newHTTPServer(s.config.Addr)

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("server starting", "addr", s.config.Addr, "domain", s.config.Domain, "version", version.Version)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("shutting down server")
		s.shutdown()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// buildDNSProvider constructs the libdns provider for the configured ACME
// DNS-01 challenge provider. It also returns it as a RecordGetter when the
// implementation supports reading (all of ours do), which the custom-domain
// verification path uses.
func buildDNSProvider(cfg Config) (certmagic.DNSProvider, libdns.RecordGetter, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.AIODNSProvider))
	if provider == "" {
		provider = "cloudflare"
	}
	switch provider {
	case "cloudflare":
		if cfg.AIOCFToken == "" {
			return nil, nil, fmt.Errorf("cloudflare provider requires --aio-cf-token")
		}
		p := &cloudflare.Provider{APIToken: cfg.AIOCFToken}
		return p, p, nil
	case "digitalocean":
		if cfg.AIOCFToken == "" {
			return nil, nil, fmt.Errorf("digitalocean provider requires --aio-cf-token (set to a DigitalOcean API token)")
		}
		p := &digitalocean.Provider{APIToken: cfg.AIOCFToken}
		return p, p, nil
	case "route53":
		if cfg.AIOCFToken == "" || cfg.AIODNSSecret == "" {
			return nil, nil, fmt.Errorf("route53 provider requires --aio-cf-token set to the AWS Access Key ID and --aio-dns-secret set to the Secret Access Key")
		}
		p := &route53.Provider{
			AccessKeyId:     cfg.AIOCFToken,
			SecretAccessKey: cfg.AIODNSSecret,
		}
		return p, p, nil
	default:
		return nil, nil, fmt.Errorf("unknown DNS provider %q (supported: cloudflare, digitalocean, route53)", cfg.AIODNSProvider)
	}
}

// runAIO starts the all-in-one server: HTTP + HTTPS (ports configurable via
// AIOHTTPPort/AIOHTTPSPort, defaults 80/443) with auto Let's Encrypt certs.
func (s *Server) runAIO(ctx context.Context) error {
	// Configure CertMagic storage.
	certmagic.Default.Storage = &certmagic.FileStorage{Path: s.config.AIOCertPath}

	// Configure ACME issuer with DNS-01 challenge via the selected provider.
	dnsProvider, dnsReader, err := buildDNSProvider(s.config)
	if err != nil {
		return err
	}
	s.dnsReader = dnsReader
	certmagic.DefaultACME.Email = s.config.AIOEmail
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: dnsProvider,
		},
	}

	// Manage certificates for the domain and wildcard.
	//
	// On-demand issuance serves verified custom domains: any SNI that is not
	// the base domain or an active custom hostname is refused, so a hostile
	// client cannot make the server mint arbitrary certificates.
	certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(_ context.Context, name string) error {
			name = strings.ToLower(strings.TrimSuffix(name, "."))
			if name == s.config.Domain || name == s.config.ControlDomain {
				return nil
			}
			if _, ok := s.tunnels.LookupCustom(name); ok {
				return nil
			}
			// Active tunnel subdomains (<sub>.<Domain>) are also legitimate
			// names; this is a fallback for when the wildcard cert is not yet
			// cached (e.g. issuance failed on a previous start).
			if strings.HasSuffix(name, "."+s.config.Domain) {
				label := strings.TrimSuffix(name, "."+s.config.Domain)
				if _, ok := s.tunnels.LookupByHost(registeredSubdomain(label)); ok {
					return nil
				}
			}
			return fmt.Errorf("certificate issuance denied for %q: not an active tunnel or custom domain", name)
		},
	}
	magic := certmagic.NewDefault()
	domains := []string{s.config.Domain, "*." + s.config.Domain}
	s.logger.Info("provisioning TLS certificates", "domains", domains)
	// Obtain the base + wildcard certs NOW, synchronously. With OnDemand
	// configured, ManageSync defers all issuance to first handshake, and the
	// DecisionFunc above would then deny wildcard subdomains -> tunnels could
	// never get TLS. ObtainCertSync bypasses the on-demand path; ManageSync
	// afterwards just registers the certs for renewal.
	for _, d := range domains {
		if err := magic.ObtainCertSync(ctx, d); err != nil {
			return fmt.Errorf("certmagic: obtain %s: %w", d, err)
		}
	}
	if err := magic.ManageSync(ctx, domains); err != nil {
		return fmt.Errorf("certmagic: %w", err)
	}
	s.logger.Info("TLS certificates ready")

	// Build TLS config from CertMagic.
	tlsConfig := magic.TLSConfig()
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}

	bind := s.config.AIOBind
	httpPort := s.config.AIOHTTPPort
	if httpPort == 0 {
		httpPort = 80
	}
	httpsPort := s.config.AIOHTTPSPort
	if httpsPort == 0 {
		httpsPort = 443
	}

	httpAddr := fmt.Sprintf("%s:%d", bind, httpPort)
	httpsAddr := fmt.Sprintf("%s:%d", bind, httpsPort)

	httpServer := s.newHTTPServer(httpAddr)
	httpsServer := s.newHTTPServer(httpsAddr)
	httpsServer.TLSConfig = tlsConfig

	errCh := make(chan error, 2)
	go func() {
		s.logger.Info("AIO HTTP server starting", "addr", httpAddr, "domain", s.config.Domain, "version", version.Version)
		errCh <- httpServer.ListenAndServe()
	}()
	go func() {
		s.logger.Info("AIO HTTPS server starting", "addr", httpsAddr, "domain", s.config.Domain, "version", version.Version)
		errCh <- httpsServer.ListenAndServeTLS("", "")
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("shutting down AIO server")
		s.shutdown()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdownCtx)
		httpsServer.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

// customDomainVerifyTimeout bounds one TXT-ownership check at connect time.
const customDomainVerifyTimeout = 15 * time.Second

// verifyCustomDomain proves that the requesting user controls a hostname by
// requiring a TXT record at _mabo-challenge.<domain> whose value is
// sha256("<sha256-of-token-hex>.<domain>") — a value only someone holding the
// real token can compute, checked against nothing but the stored hash. DNS is
// read through the ACME provider API in AIO mode (fresh data, no resolver
// cache) and via public resolvers otherwise.
func (s *Server) verifyCustomDomain(ctx context.Context, tokenHashHex, domain string) error {
	if len(s.config.CustomDomains) == 0 {
		return fmt.Errorf("custom domains are not enabled on this server")
	}
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if len(domain) > 253 || !isHostname(domain) {
		return fmt.Errorf("custom domain %q is not a valid hostname", domain)
	}
	if domain == s.config.Domain || strings.HasSuffix(domain, "."+s.config.Domain) {
		return fmt.Errorf("custom domain must be outside the base domain %q", s.config.Domain)
	}

	zone := ""
	for _, z := range s.config.CustomDomains {
		z = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(z), "."))
		if domain == z || strings.HasSuffix(domain, "."+z) {
			zone = z
			break
		}
	}
	if zone == "" {
		return fmt.Errorf("custom domain must end with one of the enabled zones (%s)", strings.Join(s.config.CustomDomains, ", "))
	}

	expected := protocol.CustomDomainChallenge(tokenHashHex, domain)
	fqdn := protocol.CustomDomainTXTLabel + "." + domain

	vctx, cancel := context.WithTimeout(ctx, customDomainVerifyTimeout)
	defer cancel()

	match := func(value string) bool {
		return strings.EqualFold(strings.TrimSpace(value), expected)
	}

	if s.dnsReader != nil {
		records, err := s.dnsReader.GetRecords(vctx, zone)
		if err != nil {
			return fmt.Errorf("reading zone %q: %w", zone, err)
		}
		for _, rec := range records {
			txt, ok := rec.(libdns.TXT)
			if !ok {
				continue
			}
			name := strings.ToLower(strings.TrimSuffix(txt.Name, "."))
			if name != "" && !strings.HasSuffix(name, "."+zone) && name != zone {
				name += "." + zone
			}
			if strings.EqualFold(name, fqdn) && match(txt.Text) {
				return nil
			}
		}
	} else {
		values, err := net.LookupTXT(fqdn)
		if err == nil {
			for _, v := range values {
				if match(v) {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("ownership not proven: no TXT record %q with the challenge value (see docs for --custom-domain)", fqdn)
}

// isHostname checks basic DNS-name syntax: dot-separated labels of letters,
// digits and hyphens.
func isHostname(s string) bool {
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// ServeHTTP routes requests: subdomain and verified custom-domain hosts go to
// the proxy, everything else to the mux.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := hostWithoutPort(r.Host)

	if host == s.config.ControlDomain {
		s.mux.ServeHTTP(w, r)
		return
	}

	if strings.HasSuffix(host, "."+s.config.Domain) {
		s.proxy.ServeHTTP(w, r)
		return
	}
	if _, ok := s.tunnels.LookupCustom(host); ok {
		s.proxy.ServeHTTP(w, r)
		return
	}

	s.mux.ServeHTTP(w, r)
}

// handleTunnelConnect handles WebSocket tunnel connections from clients.
func (s *Server) handleTunnelConnect(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("websocket upgrade failed", "error", err)
		return
	}

	// Set max message size.
	conn.SetReadLimit(maxMessageSize)

	remoteAddr := s.proxy.extractClientIP(r)

	// Authenticate the client.
	ar := handleAuth(conn, s.users, s.limiter, remoteAddr, s.logger, s.metrics)
	if ar == nil {
		conn.Close()
		return
	}

	// Query param subdomain overrides protocol-level one.
	subdomain := r.URL.Query().Get("subdomain")
	if subdomain == "" {
		subdomain = ar.Subdomain
	}

	// Determine protocol: default to HTTP.
	tunnelProtocol := r.URL.Query().Get("protocol")
	if tunnelProtocol == "" {
		tunnelProtocol = ar.Protocol
	}
	if tunnelProtocol == "" {
		tunnelProtocol = protocol.ProtocolHTTP
	}

	// Custom domains are verified here, before any registry state changes.
	customHost := ""
	if ar.CustomDomain != "" {
		if tunnelProtocol != protocol.ProtocolHTTP {
			sendAuthResponse(conn, false, "custom domains are only supported for HTTP tunnels", nil)
			conn.Close()
			return
		}
		tokenHashHex := hex.EncodeToString(ar.TokenKey[:])
		if err := s.verifyCustomDomain(r.Context(), tokenHashHex, ar.CustomDomain); err != nil {
			s.logger.Warn("custom domain rejected",
				"username", ar.User.Username,
				"domain", ar.CustomDomain,
				"error", err,
			)
			sendAuthResponse(conn, false, err.Error(), nil)
			conn.Close()
			return
		}
		customHost = strings.ToLower(strings.TrimSuffix(ar.CustomDomain, "."))
	}

	opts := RegisterOpts{
		Conn:         conn,
		Username:     ar.User.Username,
		Plan:         ar.User.Plan,
		MaxTunnels:   ar.User.MaxTunnels,
		Subdomain:    subdomain,
		SessionID:    ar.SessionID,
		Name:         ar.Name,
		AllowedIPs:   ar.AllowedIPs,
		DeniedIPs:    ar.DeniedIPs,
		BasicAuth:    ar.BasicAuth,
		CustomDomain: customHost,
		Binary:       ar.Binary,
	}
	s.metrics.Inc("mabo_tunnels_registered_total", "")

	var tunnel *Tunnel
	switch tunnelProtocol {
	case protocol.ProtocolTCP:
		var err error
		tunnel, err = s.tunnels.RegisterTCP(opts)
		if err != nil {
			s.logger.Error("failed to register TCP tunnel", "error", err, "username", ar.User.Username)
			sendAuthResponse(conn, false, err.Error(), nil)
			conn.Close()
			return
		}

		tunnelURL := fmt.Sprintf("tcp://%s:%d", s.config.Domain, tunnel.TCPPort)
		s.logger.Info("TCP tunnel registered",
			"tunnel_id", tunnel.ID,
			"subdomain", tunnel.Subdomain,
			"tcp_port", tunnel.TCPPort,
			"session_id", ar.SessionID,
			"url", tunnelURL,
			"username", ar.User.Username,
			"binary", tunnel.Binary,
		)

		// Register already published this tunnel, so a public request can be
		// writing to the same socket right now. Send the auth response through
		// the tunnel's write lock, not straight at the connection.
		if err := tunnel.WriteControl(protocol.TypeAuthResponse, &protocol.AuthResponse{
			Success:   true,
			TunnelID:  tunnel.ID,
			Subdomain: tunnel.Subdomain,
			URL:       tunnelURL,
			Username:  ar.User.Username,
			Protocol:  protocol.ProtocolTCP,
			TCPPort:   tunnel.TCPPort,
			Binary:    tunnel.Binary,
		}); err != nil {
			s.logger.Error("failed to send auth response", "error", err, "tunnel_id", tunnel.ID)
			s.tunnels.Unregister(tunnel.ID)
			conn.Close()
			return
		}

		// Start TCP proxy to accept connections and forward through the tunnel.
		tcpProxy := NewTCPProxy(tunnel, s.logger)
		go tcpProxy.Serve()

	default:
		// HTTP tunnel (existing behavior).
		var err error
		tunnel, err = s.tunnels.Register(opts)
		if err != nil {
			s.logger.Error("failed to register tunnel", "error", err, "username", ar.User.Username)
			sendAuthResponse(conn, false, err.Error(), nil)
			conn.Close()
			return
		}

		tunnel.Protocol = protocol.ProtocolHTTP
		tunnelURL := s.tunnelURL(tunnel)
		s.logger.Info("tunnel registered",
			"tunnel_id", tunnel.ID,
			"subdomain", tunnel.Subdomain,
			"session_id", ar.SessionID,
			"url", tunnelURL,
			"username", ar.User.Username,
			"binary", tunnel.Binary,
		)

		// Same as above: the tunnel is already reachable, so this write has to
		// take the tunnel's write lock.
		if err := tunnel.WriteControl(protocol.TypeAuthResponse, &protocol.AuthResponse{
			Success:   true,
			TunnelID:  tunnel.ID,
			Subdomain: tunnel.Subdomain,
			URL:       tunnelURL,
			Username:  ar.User.Username,
			Protocol:  protocol.ProtocolHTTP,
			Binary:    tunnel.Binary,
		}); err != nil {
			s.logger.Error("failed to send auth response", "error", err, "tunnel_id", tunnel.ID)
			s.tunnels.Unregister(tunnel.ID)
			conn.Close()
			return
		}
	}

	// Start read loop and ping loop.
	go s.tunnelPingLoop(tunnel)
	go s.tunnelReadLoop(tunnel)
}

// tunnelPingLoop sends periodic pings to keep the connection alive.
func (s *Server) tunnelPingLoop(tunnel *Tunnel) {
	ticker := time.NewTicker(s.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-tunnel.done:
			return
		case <-ticker.C:
			tunnel.writeMu.Lock()
			tunnel.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			err := tunnel.Conn.WriteMessage(websocket.PingMessage, nil)
			tunnel.Conn.SetWriteDeadline(time.Time{})
			tunnel.writeMu.Unlock()

			if err != nil {
				s.logger.Error("ping failed", "error", err, "tunnel_id", tunnel.ID)
				return
			}
		}
	}
}

// tunnelReadLoop reads messages from the client WebSocket and dispatches them.
//
// The loop never blocks on a socket write: every handler below either pushes to
// a buffered channel or hands off to a per-connection writer goroutine. One
// slow local server must not stall an entire tunnel.
func (s *Server) tunnelReadLoop(tunnel *Tunnel) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("panic in tunnelReadLoop", "panic", r, "tunnel_id", tunnel.ID)
		}
		s.tunnels.Unregister(tunnel.ID)
		tunnel.Conn.Close()
		s.logger.Info("tunnel disconnected",
			"tunnel_id", tunnel.ID,
			"subdomain", tunnel.Subdomain,
			"username", tunnel.Username,
		)
	}()

	// Set initial read deadline; pong handler resets it.
	tunnel.Conn.SetReadDeadline(time.Now().Add(s.pongWait))
	tunnel.Conn.SetPongHandler(func(string) error {
		tunnel.Conn.SetReadDeadline(time.Now().Add(s.pongWait))
		tunnel.mu.Lock()
		tunnel.lastActivity = time.Now()
		tunnel.mu.Unlock()
		return nil
	})

	for {
		msgType, msg, err := tunnel.Conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				s.logger.Info("tunnel closed normally", "tunnel_id", tunnel.ID)
			} else if !websocket.IsUnexpectedCloseError(err) {
				s.logger.Info("tunnel read deadline exceeded", "tunnel_id", tunnel.ID)
			} else {
				s.logger.Error("tunnel read error", "error", err, "tunnel_id", tunnel.ID)
			}
			return
		}

		// Update activity.
		tunnel.mu.Lock()
		tunnel.lastActivity = time.Now()
		tunnel.mu.Unlock()

		if msgType == websocket.BinaryMessage {
			if err := s.handleBinaryFrame(tunnel, msg); err != nil {
				s.logger.Error("fatal binary frame", "error", err, "tunnel_id", tunnel.ID)
				return
			}
			continue
		}

		env, err := protocol.ParseEnvelope(msg)
		if err != nil {
			s.logger.Error("invalid message from tunnel", "error", err, "tunnel_id", tunnel.ID)
			continue
		}

		switch env.Type {
		case protocol.TypeData:
			var frame protocol.DataFrame
			if err := env.ParsePayload(&frame); err != nil {
				s.logger.Error("invalid data frame", "error", err, "tunnel_id", tunnel.ID)
				continue
			}
			if len(frame.Data) > protocol.MaxDataFrameBytes {
				s.frameSizeViolation(tunnel, env.Type, len(frame.Data), protocol.MaxDataFrameBytes)
				return
			}
			s.handleStreamData(tunnel, frame.ConnID, frame.Data)

		case protocol.TypeRespHeader:
			var hdr protocol.RespHeaderFrame
			if err := env.ParsePayload(&hdr); err != nil {
				s.logger.Error("invalid resp_header frame", "error", err, "tunnel_id", tunnel.ID)
				continue
			}
			s.handleRespHeader(tunnel, &hdr)

		case protocol.TypeRespBody:
			var frame protocol.DataFrame
			if err := env.ParsePayload(&frame); err != nil {
				s.logger.Error("invalid resp_body frame", "error", err, "tunnel_id", tunnel.ID)
				continue
			}
			if len(frame.Data) > protocol.MaxStreamChunkBytes {
				s.frameSizeViolation(tunnel, env.Type, len(frame.Data), protocol.MaxStreamChunkBytes)
				return
			}
			s.handleRespBody(tunnel, frame.ConnID, frame.Data)

		case protocol.TypeRespEnd:
			var closeFrame protocol.CloseFrame
			if err := env.ParsePayload(&closeFrame); err != nil {
				s.logger.Error("invalid resp_end frame", "error", err, "tunnel_id", tunnel.ID)
				continue
			}
			s.handleRespEnd(tunnel, &closeFrame)

		case protocol.TypeTCPData:
			var frame protocol.DataFrame
			if err := env.ParsePayload(&frame); err != nil {
				s.logger.Error("invalid TCP data frame", "error", err, "tunnel_id", tunnel.ID)
				continue
			}
			if len(frame.Data) > protocol.MaxStreamChunkBytes {
				s.frameSizeViolation(tunnel, env.Type, len(frame.Data), protocol.MaxStreamChunkBytes)
				return
			}
			HandleTCPDataFromClient(tunnel, frame.ConnID, frame.Data, s.logger)

		case protocol.TypeClose:
			var closeFrame protocol.CloseFrame
			if err := env.ParsePayload(&closeFrame); err == nil {
				switch closeFrame.Reason {
				case "graceful":
					tunnel.graceful.Store(true)
					s.logger.Info("client signaled graceful close", "tunnel_id", tunnel.ID)
				case protocol.CloseReasonTCPEOF:
					s.closeTCPConn(tunnel, closeFrame.ConnID)
				}
			}

		case protocol.TypePong:
			// Application-level pong (WebSocket-level handled by PongHandler).

		default:
			s.logger.Warn("unknown message type from tunnel", "type", env.Type, "tunnel_id", tunnel.ID)
		}
	}
}

// handleBinaryFrame dispatches a binary data frame. A non-nil return is a
// protocol violation that must tear down the tunnel.
//
// The payload aliases the buffer gorilla allocated for this message. That
// buffer is not reused across reads, so handing it onward without a copy is
// safe and saves an allocation per chunk.
func (s *Server) handleBinaryFrame(tunnel *Tunnel, msg []byte) error {
	frameType, connID, payload, err := protocol.DecodeBinaryFrame(msg)
	if err != nil {
		s.logger.Error("invalid binary frame", "error", err, "tunnel_id", tunnel.ID)
		return nil
	}

	var limit int
	switch frameType {
	case protocol.BinTypeRespBody, protocol.BinTypeTCPData:
		limit = protocol.MaxStreamChunkBytes
	case protocol.BinTypeData:
		limit = protocol.MaxDataFrameBytes
	default:
		s.logger.Warn("unknown binary frame type", "type", frameType, "tunnel_id", tunnel.ID)
		return nil
	}
	if len(payload) > limit {
		return s.frameSizeViolation(tunnel, fmt.Sprintf("binary(%d)", frameType), len(payload), limit)
	}

	switch frameType {
	case protocol.BinTypeRespBody:
		s.handleRespBody(tunnel, connID, payload)
	case protocol.BinTypeData:
		s.handleStreamData(tunnel, connID, payload)
	case protocol.BinTypeTCPData:
		HandleTCPDataFromClient(tunnel, connID, payload, s.logger)
	}
	return nil
}

// frameSizeViolation logs a peer that sent an oversized frame and returns the
// error that ends the read loop. The per-connection queues behind these
// frames are sized for the documented chunk sizes; honoring a giant frame
// lets one frame pin megabytes per queue slot, so the tunnel comes down.
func (s *Server) frameSizeViolation(tunnel *Tunnel, frameType string, size, limit int) error {
	err := fmt.Errorf("%s frame payload %d bytes exceeds protocol limit %d", frameType, size, limit)
	s.logger.Error("protocol violation from tunnel peer — disconnecting",
		"tunnel_id", tunnel.ID,
		"username", tunnel.Username,
		"frame_type", frameType,
		"payload_bytes", size,
		"limit", limit,
	)
	return err
}

// handleStreamData routes bytes from the tunnel client for a logical
// connection. Post-streaming refactor this carries WebSocket passthrough only;
// HTTP responses use the resp_* frames handled below. Old clients may still
// send a whole buffered HTTP response here, which the legacy branch accepts.
func (s *Server) handleStreamData(tunnel *Tunnel, connID string, data []byte) {
	val, ok := tunnel.pending.Load(connID)
	if !ok {
		// Stale frame after the conn was torn down — common on cancel, not an error.
		return
	}

	switch conn := val.(type) {
	case *StreamingConn:
		if !conn.TrySend(data) {
			s.logger.Warn("streaming connection closed: consumer fell behind or connection ended",
				"conn_id", connID,
				"tunnel_id", tunnel.ID,
			)
		}
	case *ProxiedConn:
		// Legacy path: old clients may still send TypeData for HTTP responses.
		// Treat the whole blob as a single body chunk wrapped in header+body+end
		// so we stay compatible with pre-streaming tunnel clients.
		s.logger.Warn("received legacy data frame for HTTP response; tunnel client is out of date",
			"conn_id", connID,
			"tunnel_id", tunnel.ID,
		)
		conn.PushHeader(&protocol.RespHeaderFrame{
			ConnID:     connID,
			TunnelID:   tunnel.ID,
			StatusCode: 0, // signals "raw bytes, parse them"
		})
		conn.PushBody(data)
		conn.PushEnd("")
	default:
		s.logger.Warn("unknown pending connection type", "conn_id", connID)
	}
}

// handleRespHeader delivers streaming response headers to the waiting ProxiedConn.
func (s *Server) handleRespHeader(tunnel *Tunnel, hdr *protocol.RespHeaderFrame) {
	val, ok := tunnel.pending.Load(hdr.ConnID)
	if !ok {
		return
	}
	conn, ok := val.(*ProxiedConn)
	if !ok {
		s.logger.Warn("resp_header for non-HTTP conn", "conn_id", hdr.ConnID)
		return
	}
	if !conn.PushHeader(hdr) {
		s.logger.Warn("dropped resp_header (slow consumer)", "conn_id", hdr.ConnID)
	}
}

// handleRespBody delivers a streaming response body chunk.
func (s *Server) handleRespBody(tunnel *Tunnel, connID string, data []byte) {
	val, ok := tunnel.pending.Load(connID)
	if !ok {
		return
	}
	conn, ok := val.(*ProxiedConn)
	if !ok {
		return
	}
	if !conn.PushBody(data) {
		s.logger.Warn("response aborted: consumer fell behind", "conn_id", connID, "tunnel_id", tunnel.ID)
	}
}

// handleRespEnd signals end-of-stream for a proxied HTTP response.
func (s *Server) handleRespEnd(tunnel *Tunnel, cf *protocol.CloseFrame) {
	val, ok := tunnel.pending.Load(cf.ConnID)
	if !ok {
		return
	}
	conn, ok := val.(*ProxiedConn)
	if !ok {
		return
	}
	conn.PushEnd(cf.Reason)
}

// closeTCPConn tears down a logical connection the client reports as finished
// (close reason tcp_eof): a TCP-tunnel socket or a WebSocket passthrough
// stream, whose public side is closed so the browser sees a clean end rather
// than waiting on a dead local server.
func (s *Server) closeTCPConn(tunnel *Tunnel, connID string) {
	if val, ok := tunnel.tcpConns.LoadAndDelete(connID); ok {
		if w, ok := val.(*connWriter); ok {
			w.Close()
		}
		return
	}
	if val, ok := tunnel.pending.Load(connID); ok {
		if sc, ok := val.(*StreamingConn); ok {
			sc.Close()
		}
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok"}`)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	usersLoaded := s.users.Count()
	if usersLoaded == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `{"status":"not_ready","reason":"no_users_loaded"}`)
		return
	}

	fmt.Fprintf(w, `{"status":"ready","active_tunnels":%d,"users_loaded":%d}`,
		s.tunnels.ActiveCount(),
		usersLoaded,
	)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"service":"mabo-tunnel","version":%q,"domain":%q,"active_tunnels":%d}`,
		version.Version,
		s.config.Domain,
		s.tunnels.ActiveCount(),
	)
}
