package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/maborak/mabo-tunnel/internal/server"
	"github.com/maborak/mabo-tunnel/internal/upgrade"
	"github.com/maborak/mabo-tunnel/internal/version"
)

// Build-time defaults. The compiled-in values are deliberately local-only so a
// freshly built binary never talks to someone else's infrastructure. Set your
// own for a release build in one of two ways:
//
//  1. ldflags, for non-secret values:
//     go build -ldflags "-X main.defaultDomain=tunnel.example.com -X main.defaultAIOEmail=admin@example.com"
//  2. the embed-secrets tool, for values that must not sit in plain sight —
//     it generates embedded.go with an init() that decrypts them at startup.
//
// Either way, a flag or environment variable still wins at runtime.
var (
	defaultDomain       = "localhost"
	defaultUsersFile    = "data/users.txt"
	defaultAIOBind      = "0.0.0.0"
	defaultAIOEmail     = ""
	defaultAIOCertPath  = "data/certs"
	defaultAIOHTTPPort  = 80
	defaultAIOHTTPSPort = 443
	defaultAIO          = "" // set to "true" to enable AIO by default

	// Populated by generated embedded.go init() — encrypted at rest in the binary.
	embeddedAIO            bool
	embeddedDomain         string
	embeddedAIOBind        string
	embeddedAIOEmail       string
	embeddedAIOCertPath    string
	embeddedCFToken        string
	embeddedAIODNSProvider string
	embeddedAIODNSSecret   string
	embeddedUsersData      string
)

func main() {
	cfg := server.Config{}

	flag.StringVar(&cfg.Addr, "addr", envOrDefault("MABO_TUNNEL_ADDR", ":8080"), "HTTP listen address")
	flag.StringVar(&cfg.Domain, "domain", envOrDefault("MABO_TUNNEL_DOMAIN", defaultDomain), "Base domain for tunnels")
	flag.StringVar(&cfg.UsersFile, "users-file", envOrDefault("MABO_TUNNEL_USERS_FILE", defaultUsersFile), "Path to users file")
	flag.IntVar(&cfg.TCPPortMin, "tcp-port-min", envOrDefaultInt("MABO_TUNNEL_TCP_PORT_MIN", 10000), "Start of TCP port range for TCP tunnels")
	flag.IntVar(&cfg.TCPPortMax, "tcp-port-max", envOrDefaultInt("MABO_TUNNEL_TCP_PORT_MAX", 10100), "End of TCP port range for TCP tunnels")
	flag.StringVar(&cfg.LogLevel, "log-level", envOrDefault("MABO_TUNNEL_LOG_LEVEL", "info"), "Log level: debug, info, warn, error")
	flag.IntVar(&cfg.PlanFreeLimit, "plan-free-tunnels", envOrDefaultInt("MABO_TUNNEL_PLAN_FREE_TUNNELS", 0), "Concurrent tunnels for the free plan (default: 1; per-user override wins)")
	flag.IntVar(&cfg.PlanProLimit, "plan-pro-tunnels", envOrDefaultInt("MABO_TUNNEL_PLAN_PRO_TUNNELS", 0), "Concurrent tunnels for the pro plan (default: 10; per-user override wins)")
	flag.IntVar(&cfg.TunnelRateRPS, "tunnel-rps", envOrDefaultInt("MABO_TUNNEL_TUNNEL_RPS", 0), "Per-tunnel request rate cap (requests/second, 0 = unlimited)")
	flag.IntVar(&cfg.TunnelRateBurst, "tunnel-burst", envOrDefaultInt("MABO_TUNNEL_TUNNEL_BURST", 0), "Instant burst allowed above the per-tunnel rate (default: same as --tunnel-rps)")

	var trustedProxies string
	flag.StringVar(&trustedProxies, "trusted-proxies", envOrDefault("MABO_TUNNEL_TRUSTED_PROXIES", ""),
		"Comma-separated CIDRs whose X-Forwarded-For header is trusted (default: loopback and private ranges)")
	var customDomains string
	flag.StringVar(&customDomains, "custom-domains", envOrDefault("MABO_TUNNEL_CUSTOM_DOMAINS", ""),
		"Comma-separated zone suffixes under which users may register verified custom domains\n  (e.g. \"apps.example.com\" allows wilmer.apps.example.com via a TXT challenge)")

	// AIO (all-in-one) mode flags.
	cfg.AIO = defaultAIO == "true"
	flag.BoolVar(&cfg.AIO, "aio", cfg.AIO, "All-in-one mode: HTTP:80 + HTTPS:443 + auto Let's Encrypt certs")
	flag.StringVar(&cfg.AIOBind, "aio-bind", envOrDefault("MABO_TUNNEL_AIO_BIND", defaultAIOBind), "Bind IP for AIO mode")
	flag.IntVar(&cfg.AIOHTTPPort, "aio-http-port", envOrDefaultInt("MABO_TUNNEL_AIO_HTTP_PORT", defaultAIOHTTPPort), "HTTP port for AIO mode (default: 80)")
	flag.IntVar(&cfg.AIOHTTPSPort, "aio-https-port", envOrDefaultInt("MABO_TUNNEL_AIO_HTTPS_PORT", defaultAIOHTTPSPort), "HTTPS port for AIO mode (default: 443)")
	flag.StringVar(&cfg.AIOEmail, "aio-email", envOrDefault("MABO_TUNNEL_AIO_EMAIL", defaultAIOEmail), "ACME email for Let's Encrypt (AIO mode)")
	flag.StringVar(&cfg.AIOCFToken, "aio-cf-token", envOrDefault("CF_API_TOKEN", ""), "Cloudflare API token for DNS-01 challenge (AIO mode)")
	flag.StringVar(&cfg.AIOCertPath, "aio-cert-path", envOrDefault("MABO_TUNNEL_AIO_CERT_PATH", defaultAIOCertPath), "Certificate storage path (AIO mode)")
	flag.StringVar(&cfg.AIODNSProvider, "aio-dns-provider", envOrDefault("MABO_TUNNEL_AIO_DNS_PROVIDER", "cloudflare"), "DNS-01 challenge provider for AIO mode: cloudflare, digitalocean, route53")
	var dnsSecret string
	flag.StringVar(&dnsSecret, "aio-dns-secret", envOrDefault("MABO_TUNNEL_AIO_DNS_SECRET", ""), "Provider's second credential (AWS Secret Access Key for route53; unused otherwise)")
	flag.StringVar(&cfg.AdminToken, "admin-token", envOrDefault("MABO_TUNNEL_ADMIN_TOKEN", ""), "Enable the admin API (/admin/*, /metrics) guarded by this token. Empty disables both.")

	showVer := flag.Bool("version", false, "Print version and exit")
	doUpgrade := flag.Bool("upgrade", false, "Self-update this binary from GitHub Releases, then exit")
	forceUpgrade := flag.Bool("force-upgrade", false, "With --upgrade: reinstall even if already up to date")
	flag.Parse()

	// Informational modes short-circuit before config resolution and AIO
	// validation — --upgrade needs no domain, users file or ACME email.
	if *showVer {
		fmt.Println(version.Version)
		return
	}
	if *doUpgrade && embeddedAIO && !*forceUpgrade {
		fmt.Fprintln(os.Stderr, "Error: this is an AIO build carrying embedded operator config "+
			"(domain, users, certs). --upgrade would replace it with a stock release binary and "+
			"lose that config at restart. Re-run the embed-secrets flow instead, "+
			"or pass --force-upgrade to accept.")
		os.Exit(1)
	}
	if *doUpgrade {
		os.Exit(upgrade.CLI(context.Background(), upgrade.Options{
			Binary:  "server",
			Current: version.Version,
			Force:   *forceUpgrade,
		}))
	}

	if trustedProxies != "" {
		cfg.TrustedProxies = strings.Split(trustedProxies, ",")
	}
	if customDomains != "" {
		for _, z := range strings.Split(customDomains, ",") {
			if z = strings.ToLower(strings.TrimSpace(z)); z != "" {
				cfg.CustomDomains = append(cfg.CustomDomains, z)
			}
		}
	}

	// Apply encrypted embedded values (from generated embedded.go) as fallbacks.
	if embeddedAIO {
		if !cfg.AIO {
			cfg.AIO = true
		}
		if cfg.Domain == defaultDomain && embeddedDomain != "" {
			cfg.Domain = embeddedDomain
		}
		if cfg.AIOBind == defaultAIOBind && embeddedAIOBind != "" {
			cfg.AIOBind = embeddedAIOBind
		}
		if cfg.AIOEmail == "" && embeddedAIOEmail != "" {
			cfg.AIOEmail = embeddedAIOEmail
		}
		if cfg.AIOCertPath == "data/certs" && embeddedAIOCertPath != "" {
			cfg.AIOCertPath = embeddedAIOCertPath
		}
		if cfg.AIOCFToken == "" && embeddedCFToken != "" {
			cfg.AIOCFToken = embeddedCFToken
		}
		if embeddedAIODNSProvider != "" && cfg.AIODNSProvider == "cloudflare" && os.Getenv("MABO_TUNNEL_AIO_DNS_PROVIDER") == "" {
			cfg.AIODNSProvider = embeddedAIODNSProvider
		}
		if cfg.AIODNSSecret == "" && embeddedAIODNSSecret != "" {
			cfg.AIODNSSecret = embeddedAIODNSSecret
		}
		if embeddedUsersData != "" {
			cfg.EmbeddedUsers = embeddedUsersData
		}
	}

	cfg.AIODNSSecret = dnsSecret

	// Validate AIO requirements.
	if cfg.AIO {
		if cfg.AIOCFToken == "" {
			fmt.Fprintln(os.Stderr, "Error: --aio-cf-token (or CF_API_TOKEN env) is required in AIO mode")
			os.Exit(1)
		}
		if cfg.AIOEmail == "" {
			fmt.Fprintln(os.Stderr, "Error: --aio-email (or MABO_TUNNEL_AIO_EMAIL env) is required in AIO mode")
			os.Exit(1)
		}
	}

	srv, err := server.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown and hot reload.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				fmt.Println("SIGHUP: reloading users file...")
				if err := srv.ReloadUsers(); err != nil {
					fmt.Fprintf(os.Stderr, "reload failed: %v\n", err)
				}
				continue
			}
			fmt.Printf("\nReceived %v, shutting down...\n", sig)
			cancel()
			return
		}
	}()

	if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

func envOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func envOrDefaultInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			return n
		}
	}
	return defaultVal
}
