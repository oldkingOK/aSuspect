package gatherer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"

	"aSuspect/shared"
)

const sessionFileName = "aSuspect_session.json"

type SessionStore struct {
	SID       string               `json:"sid"`
	DeviceID  string               `json:"device_id"`
	SignKey   string               `json:"sign_key"`
	Username  string               `json:"username"`
	Server    string               `json:"server"`
	Cookies   []shared.CookieJSON  `json:"cookies"`
	AntiMITM  *shared.AntiMITMData `json:"anti_mitm,omitempty"`
	CSRFToken string               `json:"csrf_token,omitempty"`
	LiveJar   *cookiejar.Jar       `json:"-"`
}

func (s *SessionStore) LiveClient() *http.Client {
	return &http.Client{
		Transport: shared.NewTransport(),
		Jar:       s.LiveJar,
	}
}

func (s *SessionStore) NewClient() (*http.Client, error) {
	jar, err := s.CookieJar()
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: shared.NewTransport(),
		Jar:       jar,
	}, nil
}

func (s *SessionStore) Save() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	if err := os.WriteFile(sessionFileName, data, 0600); err != nil {
		return fmt.Errorf("write session: %w", err)
	}
	return nil
}

func LoadSession() (*SessionStore, error) {
	path := filepath.Join(workingDir(), sessionFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no session file (%s): run with -auth first, or place %s manually", path, sessionFileName)
	}

	var s SessionStore
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse session: %w", err)
	}
	if s.SID == "" {
		return nil, fmt.Errorf("session file is missing SID")
	}
	return &s, nil
}

// Validate checks whether the saved session is still usable by making
// a lightweight request to the server's onlineInfo endpoint.
// Returns true if the server accepts the session cookies (code == 0).
func (s *SessionStore) Validate(server string, port int) bool {
	client, err := s.NewClient()
	if err != nil {
		return false
	}

	host := server
	if port != 443 {
		host = fmt.Sprintf("%s:%d", server, port)
	}

	q := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
	}
	u := fmt.Sprintf("https://%s/passport/v1/user/onlineInfo?%s", host, q.Encode())

	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", shared.UserAgent)
	if s.CSRFToken != "" {
		req.Header.Set("x-csrf-token", s.CSRFToken)
	}
	req.Header.Set("x-sdp-traceid", shared.RandHex(8))

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var v struct {
		Code int `json:"code"`
	}
	json.Unmarshal(body, &v)
	return v.Code == 0
}

func (s *SessionStore) serverURL() *url.URL {
	host := s.Server
	return &url.URL{Scheme: "https", Host: host}
}

func (s *SessionStore) CookieJar() (*cookiejar.Jar, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	u := s.serverURL()
	for _, c := range s.Cookies {
		jar.SetCookies(u, []*http.Cookie{{
			Name:  c.Name,
			Value: c.Value,
		}})
	}
	return jar, nil
}

func (s *SessionStore) UpdateCookies(jar *cookiejar.Jar) {
	cookies := jar.Cookies(s.serverURL())
	s.Cookies = make([]shared.CookieJSON, len(cookies))
	for i, c := range cookies {
		s.Cookies[i] = shared.CookieJSON{
			Host: s.Server, Scheme: "https",
			Name: c.Name, Value: c.Value,
		}
	}
}

func workingDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	return dir
}
