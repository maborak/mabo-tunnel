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
	defaultDomain      = "localhost"
	defaultUsersFile   = "data/users.txt"
	defaultAIOBind     = "0.0.0.0"
	defaultAIOEmail    = ""
	defaultAIOCertPath = "data/certs"
	defaultAIO         = "" // set to "true" to enable AIO by default

	// Populated by generated embedded.go init() — encrypted at rest in the binary.
	embeddedAIO         bool
	embeddedDomain      string
	embeddedAIOBind     string
	embeddedAIOEmail    string
	embeddedAIOCertPath string
	embeddedCFToken     string
	embeddedUsersData   string
)

func main() {
	cfg := server.Config{}

	flag.StringVar(&cfg.Addr, "addr", envOrDefault("MABO_TUNNEL_ADDR", ":8080"), "HTTP listen address")
	flag.StringVar(&cfg.Domain, "domain", envOrDefault("MABO_TUNNEL_DOMAIN", defaultDomain), "Base domain for tunnels")
	flag.StringVar(&cfg.UsersFile, "users-file", envOrDefault("MABO_TUNNEL_USERS_FILE", defaultUsersFile), "Path to users file")
	flag.IntVar(&cfg.TCPPortMin, "tcp-port-min", envOrDefaultInt("MABO_TUNNEL_TCP_PORT_MIN", 10000), "Start of TCP port range for TCP tunnels")
	flag.IntVar(&cfg.TCPPortMax, "tcp-port-max", envOrDefaultInt("MABO_TUNNEL_TCP_PORT_MAX", 10100), "End of TCP port range for TCP tunnels")
	flag.StringVar(&cfg.LogLevel, "log-level", envOrDefault("MABO_TUNNEL_LOG_LEVEL", "info"), "Log level: debug, info, warn, error")

	var trustedProxies string
	flag.StringVar(&trustedProxies, "trusted-proxies", envOrDefault("MABO_TUNNEL_TRUSTED_PROXIES", ""),
		"Comma-separated CIDRs whose X-Forwarded-For header is trusted (default: loopback and private ranges)")

	// AIO (all-in-one) mode flags.
	cfg.AIO = defaultAIO == "true"
	flag.BoolVar(&cfg.AIO, "aio", cfg.AIO, "All-in-one mode: HTTP:80 + HTTPS:443 + auto Let's Encrypt certs")
	flag.StringVar(&cfg.AIOBind, "aio-bind", envOrDefault("MABO_TUNNEL_AIO_BIND", defaultAIOBind), "Bind IP for AIO mode")
	flag.StringVar(&cfg.AIOEmail, "aio-email", envOrDefault("MABO_TUNNEL_AIO_EMAIL", defaultAIOEmail), "ACME email for Let's Encrypt (AIO mode)")
	flag.StringVar(&cfg.AIOCFToken, "aio-cf-token", envOrDefault("CF_API_TOKEN", ""), "Cloudflare API token for DNS-01 challenge (AIO mode)")
	flag.StringVar(&cfg.AIOCertPath, "aio-cert-path", envOrDefault("MABO_TUNNEL_AIO_CERT_PATH", defaultAIOCertPath), "Certificate storage path (AIO mode)")

	flag.Parse()

	if trustedProxies != "" {
		cfg.TrustedProxies = strings.Split(trustedProxies, ",")
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
		if embeddedUsersData != "" {
			cfg.EmbeddedUsers = embeddedUsersData
		}
	}

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

	// Handle graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		fmt.Printf("\nReceived %v, shutting down...\n", sig)
		cancel()
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
