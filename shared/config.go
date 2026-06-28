// Package shared holds domain types and config used across the project.
package shared

import (
	"flag"
	"fmt"
)

// Config holds all CLI configuration.
type Config struct {
	// Server
	ServerAddress string
	ServerPort    int

	// Authentication — empty = load session, non-empty = login with that method
	AuthType string

	// Local proxy
	SocksBind   string
	SocksUser   string
	SocksPasswd string

	// DNS
	DNSTTL uint64

	// Behavior
	TCPMode string // "l4" (default) or "l3"

	// Output
	ShowVersion bool
	AuthInfo    bool
}

// ParseFlags parses CLI flags into a Config.
func ParseFlags(args []string) (*Config, error) {
	cfg := &Config{}
	fs := flag.NewFlagSet("aSuspect", flag.ContinueOnError)

	fs.StringVar(&cfg.ServerAddress, "server", "", "aTrust server address")
	fs.IntVar(&cfg.ServerPort, "port", 443, "aTrust server port")
	fs.StringVar(&cfg.AuthType, "auth", "", "Login method (auth/psw, auth/sms, auth/cas) or empty to load session")
	fs.StringVar(&cfg.SocksBind, "socks-bind", ":1080", "SOCKS5 listen address")
	fs.StringVar(&cfg.SocksUser, "socks-user", "", "SOCKS5 username")
	fs.StringVar(&cfg.SocksPasswd, "socks-passwd", "", "SOCKS5 password")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "Show version")
	fs.BoolVar(&cfg.AuthInfo, "auth-info", false, "Fetch server auth methods and exit")
	fs.Uint64Var(&cfg.DNSTTL, "dns-ttl", 3600, "DNS cache TTL in seconds")
	fs.StringVar(&cfg.TCPMode, "tcp-mode", "l4", "TCP tunnel mode: l4 (fast) or l3 (via gVisor)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if cfg.ShowVersion {
		return cfg, nil
	}

	if cfg.ServerAddress == "" {
		return nil, fmt.Errorf("missing required -server")
	}

	return cfg, nil
}
