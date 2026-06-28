package shared

import (
	"net"
	"sync"
)

// UserAgent mimics the official aTrust client.
const UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) aTrustTray/2.5.16.20 Chrome/83.0.4103.94 Electron/9.0.2 Safari/537.36 aTrustTray-Linux-Plat-Ubuntu-x64 SPCClientType"

// ── Protocol types ───────────────────────────────────────────────────────────

// Protocol is the IP protocol filter in resource policies.
type Protocol string

const (
	ProtoTCP  Protocol = "tcp"
	ProtoUDP  Protocol = "udp"
	ProtoAll  Protocol = "all"
	ProtoICMP Protocol = "icmp"
)

// IPResource is an IP-range resource policy from aTrust.
type IPResource struct {
	IPMin       net.IP
	IPMax       net.IP
	PortMin     int
	PortMax     int
	Protocol    Protocol
	AppID       string
	NodeGroupID string
}

// ContainsIP checks whether ip falls within this resource's IP range.
func (r IPResource) ContainsIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return bytesCompare(ip4, r.IPMin) >= 0 && bytesCompare(ip4, r.IPMax) <= 0
}

// Matches checks whether (protocol, port) is allowed by this resource.
func (r IPResource) Matches(proto Protocol, port int) bool {
	if r.Protocol != proto && r.Protocol != ProtoAll {
		return false
	}
	return port >= r.PortMin && port <= r.PortMax
}

// DomainResource is a domain-suffix resource policy from aTrust.
type DomainResource struct {
	PortMin     int
	PortMax     int
	Protocol    Protocol
	AppID       string
	NodeGroupID string
}

// Matches checks whether (protocol, port) is allowed by this resource.
func (r DomainResource) Matches(proto Protocol, port int) bool {
	if r.Protocol != proto && r.Protocol != ProtoAll {
		return false
	}
	return port >= r.PortMin && port <= r.PortMax
}

// ── Shared state ─────────────────────────────────────────────────────────────

// SharedState holds all VPN session data, shared across modules.
// Protected by RWMutex for hot-reload (node refresh).
type SharedState struct {
	SID          string
	DeviceID     string
	SignKey      string
	ConnectionID string
	Username     string

	VirtualIP net.IP

	IPResources     []IPResource
	DomainResources map[string]DomainResource // suffix → resource
	StaticHosts     map[string]net.IP         // domain → IP (server-pushed)

	DNSServer net.IP

	NodePool     map[string][]string // groupID → addresses, in server order
	MajorGroupID string

	// SPA anti-MITM data from authConfig.
	AntiMITM *AntiMITMData

	ServerAddress string
	ServerPort    int

	mu sync.RWMutex
}

// NewSharedState creates an empty SharedState.
func NewSharedState() *SharedState {
	return &SharedState{
		DomainResources: make(map[string]DomainResource),
		StaticHosts:     make(map[string]net.IP),
		NodePool:        make(map[string][]string),
	}
}

// NodeCandidates returns node addresses for groupID in server order,
// falling back to the major group if the group has no nodes.
func (s *SharedState) NodeCandidates(groupID string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nodes := s.NodePool[groupID]; len(nodes) > 0 {
		return append([]string(nil), nodes...)
	}
	if groupID != s.MajorGroupID {
		if nodes := s.NodePool[s.MajorGroupID]; len(nodes) > 0 {
			return append([]string(nil), nodes...)
		}
	}
	return nil
}

// Snapshot returns a shallow copy for read-heavy paths.
func (s *SharedState) Snapshot() SharedState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return SharedState{
		SID: s.SID, DeviceID: s.DeviceID, SignKey: s.SignKey,
		ConnectionID: s.ConnectionID, Username: s.Username,
		VirtualIP:   copyIP(s.VirtualIP),
		IPResources: s.IPResources, DomainResources: s.DomainResources,
		StaticHosts: s.StaticHosts, DNSServer: copyIP(s.DNSServer),
		NodePool:      s.NodePool,
		MajorGroupID:  s.MajorGroupID,
		AntiMITM:      s.AntiMITM,
		ServerAddress: s.ServerAddress, ServerPort: s.ServerPort,
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func bytesCompare(a, b net.IP) int {
	a4, b4 := a.To4(), b.To4()
	if a4 == nil || b4 == nil {
		return 0
	}
	for i := 0; i < 4; i++ {
		if a4[i] < b4[i] {
			return -1
		}
		if a4[i] > b4[i] {
			return 1
		}
	}
	return 0
}

// CookieJSON is used for serializing HTTP cookies.
type CookieJSON struct {
	Host   string `json:"host"`
	Scheme string `json:"scheme"`
	Name   string `json:"name"`
	Value  string `json:"value"`
}

// AntiMITMData holds SPA knocking parameters from authConfig.
type AntiMITMData struct {
	Enable             int    `json:"enable"`
	AntiMITMRequest    bool   `json:"antiMITMRequest"`
	Challenge          string `json:"challenge"`
	EncryptedChallenge string `json:"encryptedChallenge"`
	DevicePubKeyMod    string `json:"devicePubKeyMod"`
	DevicePubKeyExp    string `json:"devicePubKeyExp"`
}

// NeedsSPA reports whether SPA knocking is required.
func (a *AntiMITMData) NeedsSPA() bool {
	return a != nil && a.Enable == 1 && a.AntiMITMRequest
}

func copyIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}
