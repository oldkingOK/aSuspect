package shared

import (
	"fmt"
	"net"
	"sync"
)

// SpecialLoginIP is the virtual IP that aSuspect intercepts to serve the
// CAS/OAuth2 login page during pre-authentication phase.
var SpecialLoginIP = net.IPv4(10, 248, 98, 2)

// LoginGate manages the pre-authentication state for CAS/OAuth2 login.
// When pending, connections to SpecialLoginIP are intercepted and redirected
// to fakeProxy. After login completes, the gate is set to "ready" and
// normal VPN routing takes over.
//
// Port mapping:
//   - Port 80/443 (user's initial visit) → forwarded to fakeProxy entry port,
//     which 302-redirects to the proxy port with correct Host header.
//   - All other ports → forwarded to 127.0.0.1:<same_port>. This is
//     port-preserving passthrough for fakeProxy's proxy port and dynamically
//     created route ports (one per upstream SSO origin).
type LoginGate struct {
	mu        sync.RWMutex
	status    string // "pending" | "ready" | "failed"
	entryPort int    // fakeProxy entry port
}

// NewLoginGate creates a LoginGate in "ready" state (no pending login).
func NewLoginGate() *LoginGate {
	return &LoginGate{status: "ready"}
}

// SetPending marks the gate as pending and records the fakeProxy entry port.
func (g *LoginGate) SetPending(entryPort int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.status = "pending"
	g.entryPort = entryPort
}

// SetReady marks the gate as ready (login complete, normal routing).
func (g *LoginGate) SetReady() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.status = "ready"
}

// SetFailed marks the gate as failed (login rejected).
func (g *LoginGate) SetFailed() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.status = "failed"
}

// Intercept checks whether a connection to the given IP:port should be
// intercepted and redirected to fakeProxy. Returns the local address
// to dial instead, and true if interception is active.
func (g *LoginGate) Intercept(ip net.IP, port int) (string, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.status != "pending" || !ip.Equal(SpecialLoginIP) {
		return "", false
	}
	// Port 80 (HTTP) or 443 (HTTPS): user's initial visit, forward to entry port.
	if port == 80 || port == 443 {
		return fmt.Sprintf("127.0.0.1:%d", g.entryPort), true
	}
	// Other ports: port-preserving passthrough to fakeProxy's proxy/route ports.
	return fmt.Sprintf("127.0.0.1:%d", port), true
}

// IsPending reports whether the gate is waiting for login completion.
func (g *LoginGate) IsPending() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.status == "pending"
}
