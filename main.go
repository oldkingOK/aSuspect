package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"

	"aSuspect/auth"
	"aSuspect/gatherer"
	"aSuspect/proxy"
	"aSuspect/shared"

	"github.com/things-go/go-socks5"
)

var appVersion = "dev"

func main() {
	cfg, err := shared.ParseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "aSuspect:", err)
		os.Exit(2)
	}

	if cfg.ShowVersion {
		fmt.Printf("aSuspect %s\n", appVersion)
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

	// Try saved session first — even if -auth is specified, a valid
	// cached session avoids an unnecessary re-login.
	if s, err := gatherer.LoadSession(); err == nil && s.Validate(cfg.ServerAddress, cfg.ServerPort) {
		session = s
		client, _ = s.NewClient()
		log.Printf("Using saved session for %s", s.Username)
	}

	// CAS async path: start SOCKS5 immediately, serve login page on 10.248.98.2.
	if session == nil && cfg.AuthType == "auth/cas" {
		return runCASAsync(cfg)
	}

	// Other auth methods: blocking login.
	if session == nil && cfg.AuthType != "" {
		s, err := doLogin(cfg)
		if err != nil {
			return fmt.Errorf("login: %w", err)
		}
		session = s
		client = s.LiveClient()
	}

	if session == nil {
		return fmt.Errorf("no valid session (run with -auth first)")
	}

	return runProxy(cfg, session, client)
}

// runProxy gathers resources and starts the full SOCKS5 proxy.
func runProxy(cfg *shared.Config, session *gatherer.SessionStore, client *http.Client) error {
	log.Printf("Logged in as %s", session.Username)

	// ── Gather resources ────────────────────────────────────────────
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

	// ── Start proxy ──────────────────────────────────────────────────
	p, err := proxy.New(cfg, state)
	if err != nil {
		return fmt.Errorf("create proxy: %w", err)
	}
	return p.Serve()
}

// runCASAsync runs the CAS/OAuth2 login flow without blocking SOCKS5 startup.
// A pre-login SOCKS5 server starts immediately and intercepts connections to
// 10.248.98.2, forwarding them to the fakeProxy login page. Once the user
// completes SSO in the browser, the full VPN proxy takes over on the same port.
func runCASAsync(cfg *shared.Config) error {
	// 1. Initialize auth session and fetch config.
	authSess := auth.NewSession(cfg.ServerAddress, cfg.ServerPort, "")

	authCfg, err := authSess.FetchAuthConfig()
	if err != nil {
		return fmt.Errorf("fetch auth config: %w", err)
	}
	if authCfg.IsLogin == 1 {
		creds, err := authSess.Credentials()
		if err != nil {
			return fmt.Errorf("credentials: %w", err)
		}
		session := sessionFromCreds(creds, cfg.ServerAddress)
		session.Save()
		return runProxy(cfg, session, session.LiveClient())
	}

	// 2. Resolve CAS login URL.
	loginURL, err := authSess.ResolveRedirectAuth()
	if err != nil {
		return fmt.Errorf("resolve CAS URL: %w", err)
	}

	// 3. Start CAS login (non-blocking).
	ctx := context.Background()
	handle, err := authSess.StartCASLogin(ctx, loginURL)
	if err != nil {
		return fmt.Errorf("start CAS login: %w", err)
	}
	defer handle.Close()

	// 4. Create LoginGate with fakeProxy entry port.
	u, _ := url.Parse(handle.EntryURL)
	fakeProxyPort, _ := strconv.Atoi(u.Port())
	loginGate := shared.NewLoginGate()
	loginGate.SetPending(fakeProxyPort)

	// 5. Start pre-login SOCKS5 server.
	socksCtx, socksCancel := context.WithCancel(context.Background())
	defer socksCancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := servePreLoginSOCKS5(socksCtx, cfg, loginGate); err != nil {
			log.Printf("pre-login SOCKS5: %v", err)
		}
	}()

	// 6. Print URLs for both access methods.
	fmt.Printf("SOCKS5 server listening on %s\n", cfg.SocksBind)
	fmt.Printf("Open this URL in your browser:\n  %s\n", handle.EntryURL)
	fmt.Printf("Or http://%s/ via socks5://%s\n", shared.SpecialLoginIP, cfg.SocksBind)

	// 7. Wait for CAS callback.
	callback, err := handle.Wait(ctx)
	if err != nil {
		loginGate.SetFailed()
		return fmt.Errorf("CAS login: %w", err)
	}

	// 8. Complete CAS login.
	if err := authSess.CompleteCASLogin(callback); err != nil {
		loginGate.SetFailed()
		return fmt.Errorf("complete CAS login: %w", err)
	}

	// 9. Report environment.
	if err := authSess.ReportEnv(); err != nil {
		return fmt.Errorf("reportEnv: %w", err)
	}

	// 10. Check secondary auth (SMS 2FA).
	authID, err := authSess.AuthCheck()
	if err != nil {
		return fmt.Errorf("authCheck: %w", err)
	}
	if authID != "" {
		if err := authSess.AuthSms(authID); err != nil {
			return fmt.Errorf("secondary SMS: %w", err)
		}
		if err := authSess.SmsVerify(authID); err != nil {
			return fmt.Errorf("secondary SMS verify: %w", err)
		}
	}

	// 11. Extract credentials and save session.
	creds, err := authSess.Credentials()
	if err != nil {
		loginGate.SetFailed()
		return fmt.Errorf("credentials: %w", err)
	}

	session := sessionFromCreds(creds, cfg.ServerAddress)
	if err := session.Save(); err != nil {
		return fmt.Errorf("save session: %w", err)
	}

	log.Printf("Login successful")
	loginGate.SetReady()

	// 12. Stop pre-login SOCKS5 before starting the full proxy.
	socksCancel()
	wg.Wait()

	// 13. Start full VPN proxy.
	return runProxy(cfg, session, session.LiveClient())
}

// servePreLoginSOCKS5 starts a minimal SOCKS5 server that only intercepts
// connections to SpecialLoginIP and redirects them to fakeProxy. All other
// connections are rejected with a helpful message.
func servePreLoginSOCKS5(ctx context.Context, cfg *shared.Config, loginGate *shared.LoginGate) error {
	var authMethods []socks5.Authenticator
	if cfg.SocksUser != "" {
		authMethods = append(authMethods,
			socks5.UserPassAuthenticator{
				Credentials: socks5.StaticCredentials{
					cfg.SocksUser: cfg.SocksPasswd,
				},
			})
	} else {
		authMethods = append(authMethods, socks5.NoAuthAuthenticator{})
	}

	preDial := func(_ context.Context, network, addr string) (net.Conn, error) {
		if network == "tcp" {
			host, portStr, err := net.SplitHostPort(addr)
			if err == nil {
				port, _ := strconv.Atoi(portStr)
				if fpAddr, ok := loginGate.Intercept(net.ParseIP(host), port); ok {
					return net.Dial("tcp", fpAddr)
				}
			}
		}
		return nil, fmt.Errorf("not authenticated — visit http://%s/ to log in", shared.SpecialLoginIP)
	}

	server := socks5.NewServer(
		socks5.WithAuthMethods(authMethods),
		socks5.WithDial(preDial),
		socks5.WithLogger(socks5.NewLogger(
			log.New(os.Stdout, "[SOCKS5] ", log.LstdFlags),
		)),
	)

	listener, err := net.Listen("tcp", cfg.SocksBind)
	if err != nil {
		return fmt.Errorf("SOCKS5 listen: %w", err)
	}

	log.Printf("SOCKS5 server listening on %s (pre-login mode)", cfg.SocksBind)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	return server.Serve(listener)
}

func doLogin(cfg *shared.Config) (*gatherer.SessionStore, error) {
	method, err := resolveAuthMethod(cfg.AuthType)
	if err != nil {
		return nil, err
	}

	creds, err := auth.Login(cfg.ServerAddress, cfg.ServerPort, method, "")
	if err != nil {
		return nil, err
	}

	log.Printf("Login successful")

	session := sessionFromCreds(creds, cfg.ServerAddress)
	if err := session.Save(); err != nil {
		return nil, fmt.Errorf("save session: %w", err)
	}

	return session, nil
}

func resolveAuthMethod(authType string) (auth.Authenticator, error) {
	switch authType {
	case "auth/psw":
		return &auth.PasswordAuth{}, nil
	case "auth/sms":
		return &auth.SMSAuth{}, nil
	case "auth/cas":
		return &auth.RedirectAuth{}, nil
	default:
		return nil, fmt.Errorf("unknown auth type: %s", authType)
	}
}

// sessionFromCreds converts auth credentials into a session store.
// This is wiring-layer code — it translates between auth and gatherer types.
func sessionFromCreds(creds *auth.Credentials, server string) *gatherer.SessionStore {
	return &gatherer.SessionStore{
		SID:       creds.SID,
		DeviceID:  creds.DeviceID,
		SignKey:   creds.SignKey,
		Username:  creds.Username,
		Server:    server,
		Cookies:   creds.Cookies,
		AntiMITM:  creds.AntiMITM,
		CSRFToken: creds.CSRFToken,
		LiveJar:   creds.Jar,
	}
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
