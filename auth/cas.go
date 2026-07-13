package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/signal"
	"strings"
	"syscall"

	fakeproxy "github.com/doctxing/fakeProxy/core"

	"aSuspect/shared"
)

// RedirectAuth handles redirect-based SSO login (CAS, OAuth2, httpsOauth2).
type RedirectAuth struct{}

// CASLoginHandle holds the state of an in-progress CAS/OAuth2 login.
// Call Wait() to block until the callback arrives, or Close() to abort.
type CASLoginHandle struct {
	EntryURL   string
	CallbackCh <-chan string
	proxy      *fakeproxy.Server
	cancel     context.CancelFunc
	sigCtx     context.Context
}

// Wait blocks until the CAS callback is received, the context is cancelled,
// or an interrupt signal arrives.
func (h *CASLoginHandle) Wait(ctx context.Context) (string, error) {
	select {
	case callback := <-h.CallbackCh:
		return callback, nil
	case <-ctx.Done():
		return "", ctx.Err()
	case <-h.sigCtx.Done():
		return "", h.sigCtx.Err()
	}
}

// Close shuts down the fakeProxy server and cancels signal handling.
func (h *CASLoginHandle) Close() {
	h.cancel()
	h.proxy.Close()
}

func (a RedirectAuth) Login(s *Session) error {
	loginURL, err := s.resolveRedirectAuth()
	if err != nil {
		return err
	}

	callbackURL, err := s.interactiveLogin(loginURL)
	if err != nil {
		return fmt.Errorf("interactive login: %w", err)
	}

	if err := s.CompleteCASLogin(callbackURL); err != nil {
		return fmt.Errorf("complete auth: %w", err)
	}

	return nil
}

// ResolveRedirectAuth returns the CAS/OAuth2 login URL from the auth config.
func (s *Session) ResolveRedirectAuth() (string, error) {
	return s.resolveRedirectAuth()
}

func (s *Session) resolveRedirectAuth() (string, error) {
	if s.authConfigData == nil {
		return "", fmt.Errorf("no auth config data")
	}

	if len(s.authConfigData.FirstAuth) > 0 {
		return s.resolveURL(s.authConfigData.FirstAuth[0]), nil
	}

	for _, m := range s.authConfigData.AuthServerInfoList {
		if m.LoginURL != "" {
			return s.resolveURL(m.LoginURL), nil
		}
	}

	return "", fmt.Errorf("no redirect-based auth method found")
}

func (s *Session) resolveURL(raw string) string {
	if strings.HasPrefix(raw, "/") {
		return fmt.Sprintf("https://%s:%d%s", s.server, s.port, raw)
	}
	return raw
}

func (s *Session) interactiveLogin(loginURL string) (string, error) {
	ctx := context.Background()
	handle, err := s.StartCASLogin(ctx, loginURL)
	if err != nil {
		return "", err
	}
	defer handle.Close()

	fmt.Printf("\nOpen this URL in your browser:\n  %s\n\nWaiting for login...\n", handle.EntryURL)

	return handle.Wait(ctx)
}

// StartCASLogin starts the fakeProxy and begins the CAS/OAuth2 login flow.
// It returns immediately with a handle; call Wait() to block for completion
// or use CallbackCh to receive the callback asynchronously.
func (s *Session) StartCASLogin(ctx context.Context, loginURL string) (*CASLoginHandle, error) {
	sigCtx, sigCancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)

	callbackCh := make(chan string, 1)

	proxy, err := fakeproxy.New(fakeproxy.Config{
		ResponseHook: func(fp *fakeproxy.Server, ev fakeproxy.ResponseEvent) bool {
			loc := ev.ResponseHeader.Get("Location")
			if loc == "" {
				return true
			}
			u, err := url.Parse(loc)
			if err != nil {
				return true
			}
			q := u.Query()
			if q.Get("ticket") == "" && q.Get("code") == "" {
				return true
			}
			callback := fmt.Sprintf("https://%s:%d%s?%s", s.server, s.port, u.Path, u.RawQuery)
			select {
			case callbackCh <- callback:
			default:
			}
			go fp.Close()
			return false
		},
	})
	if err != nil {
		sigCancel()
		return nil, fmt.Errorf("create proxy: %w", err)
	}

	result, err := proxy.Start(sigCtx, loginURL)
	if err != nil {
		sigCancel()
		return nil, fmt.Errorf("start proxy: %w", err)
	}

	return &CASLoginHandle{
		EntryURL:   result.EntryURL,
		CallbackCh: callbackCh,
		proxy:      proxy,
		cancel:     sigCancel,
		sigCtx:     sigCtx,
	}, nil
}

// CompleteCASLogin finishes the CAS/OAuth2 login after the callback arrives.
// It completes the redirect auth and refreshes the auth config.
func (s *Session) CompleteCASLogin(callbackURL string) error {
	if err := s.completeRedirectAuth(callbackURL); err != nil {
		return fmt.Errorf("complete auth: %w", err)
	}
	if err := s.fetchAuthConfigMod(); err != nil {
		return fmt.Errorf("authConfigMod: %w", err)
	}
	return nil
}

func (s *Session) completeRedirectAuth(callbackURL string) error {
	originalCheckRedirect := s.client.CheckRedirect
	s.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() { s.client.CheckRedirect = originalCheckRedirect }()

	req, _ := http.NewRequest("GET", callbackURL, nil)
	req.Header.Set("User-Agent", shared.UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", randSdpID())

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		return fmt.Errorf("expected 302, got %d, body: %s", resp.StatusCode, string(body))
	}

	ticket, err := parsePortalTicket(resp.Header.Get("Location"))
	if err != nil {
		return err
	}

	s.ticket = ticket
	return nil
}

func parsePortalTicket(location string) (string, error) {
	u, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("parse location: %w", err)
	}

	data := u.Query().Get("data")
	if data == "" {
		return "", fmt.Errorf("no data param in %s", location)
	}

	var v struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal([]byte(data), &v); err != nil {
		return "", fmt.Errorf("parse json: %w", err)
	}
	if v.Ticket == "" {
		return "", fmt.Errorf("empty ticket in data: %s", data)
	}

	return v.Ticket, nil
}
