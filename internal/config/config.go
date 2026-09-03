package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// HeaderConfig defines header manipulation rules for a tunnel.
type HeaderConfig struct {
	Add    map[string]string `yaml:"add,omitempty"`
	Remove []string          `yaml:"remove,omitempty"`
}

// TunnelConfig defines a single tunnel in the YAML config.
type TunnelConfig struct {
	Port         int          `yaml:"port"`
	Host         string       `yaml:"host,omitempty"` // forward target host (default: localhost)
	Auth         string       `yaml:"auth,omitempty"` // "user:pass" for HTTP Basic Auth
	CustomDomain string       `yaml:"custom_domain,omitempty"`
	Headers      HeaderConfig `yaml:"headers,omitempty"`
	AllowIPs     []string     `yaml:"allow_ips,omitempty"` // CIDRs/IPs allowed to reach this tunnel
	DenyIPs      []string     `yaml:"deny_ips,omitempty"`  // CIDRs/IPs blocked from this tunnel (checked first)
}

// FileConfig represents the full mabo-tunnel.yml configuration file.
type FileConfig struct {
	Server  string                  `yaml:"server,omitempty"`
	Token   string                  `yaml:"token,omitempty"`
	Tunnels map[string]TunnelConfig `yaml:"tunnels,omitempty"`
}

// Load reads and parses a YAML config file. Returns nil config (not an error)
// if the file does not exist, so callers can treat it as optional.
func Load(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg FileConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	// Validate tunnel ports.
	for name, t := range cfg.Tunnels {
		if t.Port <= 0 || t.Port > 65535 {
			return nil, fmt.Errorf("tunnel %q: invalid port %d", name, t.Port)
		}
	}

	return &cfg, nil
}
