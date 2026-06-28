package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"aSuspect/auth"
	"aSuspect/gatherer"
	"aSuspect/proxy"
	"aSuspect/shared"
)

const appVersion = "0.2.0"

func main() {
	cfg, err := shared.ParseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "aSuspect:", err)
		os.Exit(2)
	}

	if cfg.ShowVersion {
		fmt.Printf("aSuspect v%s\n", appVersion)
		return
	}

	if cfg.AuthInfo {
		printAuthInfo(cfg)
		return
	}

	if err := run(cfg); err != nil {
		log.Fatalf("aSuspect: %s", err)
	}
}

func run(cfg *shared.Config) error {
	// ── 1. Load or create session ──────────────────────────────────────
	var session *gatherer.SessionStore
	var client *http.Client

	if cfg.AuthType != "" {
		s, err := doLogin(cfg)
		if err != nil {
			return fmt.Errorf("login: %w", err)
		}
		session = s
		client = s.LiveClient()
	} else {
		s, err := gatherer.LoadSession()
		if err != nil {
			return fmt.Errorf("load session: %w", err)
		}
		session = s
		client, err = s.NewClient()
		if err != nil {
			return fmt.Errorf("create client: %w", err)
		}
	}

	log.Printf("Logged in as %s", session.Username)

	// ── 2. Gather resources ────────────────────────────────────────────
	g := &gatherer.InfoGatherer{
		Server:  cfg.ServerAddress,
		Port:    cfg.ServerPort,
		Session: session,
		Client:  client,
	}

	state, err := g.Gather()
	if err != nil {
		return fmt.Errorf("gather resources: %w", err)
	}

	log.Printf("Resources: %d IP ranges, %d domain suffixes, %d static hosts",
		len(state.IPResources), len(state.DomainResources), len(state.StaticHosts))

	// ── 3. Start proxy ────────────────────────────────────────────────
	p, err := proxy.New(cfg, state)
	if err != nil {
		return fmt.Errorf("create proxy: %w", err)
	}
	return p.Serve()
}

func doLogin(cfg *shared.Config) (*gatherer.SessionStore, error) {
	// Pick the right authenticator based on -auth-type.
	var method auth.Authenticator
	switch cfg.AuthType {
	case "auth/psw":
		method = &auth.PasswordAuth{}
	case "auth/sms":
		method = &auth.SMSAuth{}
	case "auth/cas":
		method = &auth.RedirectAuth{}
	default:
		return nil, fmt.Errorf("unknown auth type: %s", cfg.AuthType)
	}

	creds, err := auth.Login(cfg.ServerAddress, cfg.ServerPort, method, "")
	if err != nil {
		return nil, err
	}

	log.Printf("Login successful")

	// Save session.
	session := &gatherer.SessionStore{
		SID:       creds.SID,
		DeviceID:  creds.DeviceID,
		SignKey:   creds.SignKey,
		Username:  creds.Username,
		Server:    cfg.ServerAddress,
		Cookies:   creds.Cookies,
		AntiMITM:  creds.AntiMITM,
		CSRFToken: creds.CSRFToken,
		LiveJar:   creds.Jar,
	}
	if err := session.Save(); err != nil {
		return nil, fmt.Errorf("save session: %w", err)
	}

	return session, nil
}

func printAuthInfo(cfg *shared.Config) {
	methods, err := auth.FetchAuthMethods(cfg.ServerAddress, cfg.ServerPort)
	if err != nil {
		log.Fatalf("auth-info: %s", err)
	}
	fmt.Printf("Server: %s:%d\n", cfg.ServerAddress, cfg.ServerPort)
	fmt.Println("Supported auth methods:")
	for _, m := range methods {
		fmt.Printf("  %-20s %-20s domain=%s\n", m.AuthType, m.AuthName, m.LoginDomain)
	}
}
