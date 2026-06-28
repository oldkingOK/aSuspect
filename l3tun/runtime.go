package l3tun

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

	"aSuspect/shared"
)

// Runtime owns the L3 tunnel, gVisor stack, and packet bridge.
type Runtime struct {
	state  *shared.SharedState
	stack  *gvisorStack
	tunnel *tunnel
}

// NewRuntime initializes L3, obtains the real VIP, and creates the gVisor stack.
func NewRuntime(state *shared.SharedState, spaExt []byte) (*Runtime, error) {
	tunnel, err := newTunnel(
		state.SID,
		state.DeviceID,
		state.ConnectionID,
		state.Username,
		state.SignKey,
	)
	if err != nil {
		return nil, fmt.Errorf("L3 tunnel: %w", err)
	}
	tunnel.SpaExt = spaExt

	if err := assignVIP(state, tunnel); err != nil {
		tunnel.Close()
		return nil, err
	}

	stack, err := newGvisorStack(state.VirtualIP)
	if err != nil {
		tunnel.Close()
		return nil, fmt.Errorf("gVisor stack: %w", err)
	}

	return &Runtime{
		state:  state,
		stack:  stack,
		tunnel: tunnel,
	}, nil
}

// Stack returns the L3 userspace stack used by DNS and L3 TCP/UDP routing.
func (r *Runtime) Stack() Stack {
	return r.stack
}

// Run bridges packets between gVisor and the L3 tunnel until ctx is cancelled.
func (r *Runtime) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r.runEgress(ctx)
	}()
	go func() {
		defer wg.Done()
		r.runIngress(ctx)
	}()
	wg.Wait()
}

// Close shuts down the L3 runtime.
func (r *Runtime) Close() {
	if r.stack != nil {
		r.stack.Close()
	}
	if r.tunnel != nil {
		r.tunnel.Close()
	}
}

func assignVIP(state *shared.SharedState, tunnel *tunnel) error {
	var vipOnce sync.Once
	vipDone := make(chan struct{})
	tunnel.OnVIP = func(ips []net.IP) {
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				vipOnce.Do(func() {
					state.VirtualIP = v4
					log.Printf("L3 VIP: %s", ip)
					close(vipDone)
				})
				return
			}
		}
	}

	nodeAddrs := state.NodeCandidates(state.MajorGroupID)
	if len(nodeAddrs) > 0 {
		go func() {
			for _, nodeAddr := range nodeAddrs {
				if _, err := tunnel.EnsureConn(nodeAddr); err != nil {
					log.Printf("L3 initial connect %s: %s", nodeAddr, err)
					continue
				}
				vipOnce.Do(func() { close(vipDone) })
				return
			}
			vipOnce.Do(func() { close(vipDone) })
		}()
		<-vipDone
	}
	if state.VirtualIP == nil {
		return fmt.Errorf("L3 VIP was not assigned by the tunnel handshake")
	}
	return nil
}

func (r *Runtime) runEgress(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case rawPkt, ok := <-r.stack.EgressChan():
			if !ok {
				return
			}
			parsed, err := parseIPv4Packet(rawPkt)
			if err != nil {
				continue
			}
			r.writeEgressPacket(rawPkt, parsed)
		}
	}
}

func (r *Runtime) writeEgressPacket(rawPkt []byte, parsed parsedPacket) {
	snap := r.state.Snapshot()

	var appID, ngID string
	for _, res := range snap.IPResources {
		if res.ContainsIP(parsed.DstIP) {
			proto := l3ResourceProto(parsed.Proto)
			if res.Matches(proto, int(parsed.DstPort)) {
				appID = res.AppID
				ngID = res.NodeGroupID
				break
			}
		}
	}

	nodeAddrs := snap.NodeCandidates(ngID)
	if len(nodeAddrs) == 0 {
		return
	}

	for _, nodeAddr := range nodeAddrs {
		conn, err := r.tunnel.EnsureConn(nodeAddr)
		if err != nil {
			log.Printf("L3 egress bridge connect %s: %s", nodeAddr, err)
			continue
		}

		if appID != "" {
			err = r.tunnel.WritePacket(conn, parsed.SrcIP, parsed.SrcPort,
				parsed.DstIP, parsed.DstPort, parsed.Proto, appID, rawPkt)
		} else {
			err = conn.WriteRaw(rawPkt)
		}
		if err == nil {
			return
		}
		log.Printf("L3 egress bridge write %s: %s", nodeAddr, err)
	}
}

func (r *Runtime) runIngress(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case rawPkt, ok := <-r.tunnel.Incoming:
			if !ok {
				return
			}
			r.stack.DeliverInbound(rawPkt)
		}
	}
}

func l3ResourceProto(proto uint8) shared.Protocol {
	switch proto {
	case 17:
		return shared.ProtoUDP
	case 1:
		return shared.ProtoICMP
	default:
		return shared.ProtoTCP
	}
}
