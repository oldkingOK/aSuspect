package proxy

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"aSuspect/l3tun"
	"aSuspect/l4quic"
	"aSuspect/shared"
)

// router makes routing decisions for each SOCKS5 request.
type router struct {
	state   *shared.SharedState
	l4T     *l4quic.Tunnel
	gstack  l3tun.Stack
	tcpMode string // "l4" or "l3"
}

type routeContext struct {
	domainResource *shared.DomainResource
	ipResource     *shared.IPResource
	useVPN         bool
}

func newRouter(
	state *shared.SharedState,
	l4t *l4quic.Tunnel,
	gs l3tun.Stack,
	tcpMode string,
) *router {
	if tcpMode == "" {
		tcpMode = "l4"
	}
	return &router{
		state:   state,
		l4T:     l4t,
		gstack:  gs,
		tcpMode: tcpMode,
	}
}

// dialTCP routes a TCP connection.
//
// Decision:
//
//  1. Match domain/IP resources → VPN
//  2. No match → drop
//  3. VPN + tcpMode=l4 → L4 TCP Tunnel (dedicated TLS per connection)
//  4. VPN + tcpMode=l3 → gVisor stack → L3 Tunnel
func (r *router) dialTCP(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}

	targetIP := net.ParseIP(host)
	domain, _ := ctx.Value(ctxKeyResolveHost).(string)
	if domain == "" && targetIP == nil {
		domain = host
	}
	if targetIP == nil {
		// Domain not resolved yet — the SOCKS5 resolver should have
		// already done DNS.  If targetIP is nil here, it means
		// the resolver didn't resolve (direct connection case).
	}

	snap := r.state.Snapshot()

	// ── Resource matching ────────────────────────────────────────────
	ctx2 := &routeContext{}

	if res, ok := ctx.Value(ctxKeyDomainResource).(*shared.DomainResource); ok && res != nil {
		ctx2.domainResource = res
		ctx2.useVPN = res.Matches(shared.ProtoTCP, port)
	}

	if !ctx2.useVPN && domain != "" {
		for suffix, res := range snap.DomainResources {
			if strings.HasSuffix(domain, suffix) && res.Matches(shared.ProtoTCP, port) {
				ctx2.domainResource = &res
				ctx2.useVPN = true
				break
			}
		}
	}

	if !ctx2.useVPN && targetIP != nil {
		for i := range snap.IPResources {
			res := &snap.IPResources[i]
			if res.ContainsIP(targetIP) && res.Matches(shared.ProtoTCP, port) {
				ctx2.ipResource = res
				ctx2.useVPN = true
				break
			}
		}
	}

	// ── No resource match → drop ──────────────────────────────────
	if !ctx2.useVPN {
		return nil, fmt.Errorf("route: %s:%d does not match any aTrust resource — dropped", host, port)
	}

	// ── VPN: resolve app and node group ─────────────────────────────
	appID, ngID := r.resolveAppAndGroup(ctx2)
	nodeAddrs := snap.NodeCandidates(ngID)
	if len(nodeAddrs) == 0 {
		return nil, fmt.Errorf("no available node for group %q", ngID)
	}

	// ── Route to tunnel ─────────────────────────────────────────────
	switch r.tcpMode {
	case "l3":
		// TCP via gVisor stack → L3 tunnel.
		if targetIP == nil {
			return nil, fmt.Errorf("L3 TCP requires resolved IP address for %s", host)
		}
		return r.gstack.DialTCP(&net.TCPAddr{IP: targetIP, Port: port})
	default:
		// TCP via L4 dedicated tunnel.
		tunnelDomain := domain
		if targetIP != nil {
			tunnelDomain = ""
		}
		var lastErr error
		for _, nodeAddr := range nodeAddrs {
			conn, err := r.l4T.Dial(nodeAddr, targetIP, port, tunnelDomain, appID)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("L4 dial via nodes: %w", lastErr)
	}
}

// dialUDP creates a UDP connection through gVisor stack → L3 tunnel.
func (r *router) dialUDP(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}

	targetIP := net.ParseIP(host)
	if targetIP == nil {
		return nil, fmt.Errorf("UDP requires resolved IP address")
	}

	// Match resource for routing.
	var useVPN bool
	snap := r.state.Snapshot()
	for i := range snap.IPResources {
		if snap.IPResources[i].ContainsIP(targetIP) && snap.IPResources[i].Matches(shared.ProtoUDP, port) {
			useVPN = true
			break
		}
	}

	if !useVPN {
		return nil, fmt.Errorf("route: %s:%d does not match any aTrust resource — dropped", targetIP, port)
	}

	// VPN: gVisor stack → L3 tunnel.
	return r.gstack.DialUDPConn(
		&net.UDPAddr{IP: snap.VirtualIP, Port: 0}, // ephemeral port
		&net.UDPAddr{IP: targetIP, Port: port},
	)
}

func (r *router) resolveAppAndGroup(ctx *routeContext) (string, string) {
	if ctx.domainResource != nil {
		return ctx.domainResource.AppID, ctx.domainResource.NodeGroupID
	}
	if ctx.ipResource != nil {
		return ctx.ipResource.AppID, ctx.ipResource.NodeGroupID
	}
	return "", r.state.MajorGroupID
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", s, err)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return p, nil
}
