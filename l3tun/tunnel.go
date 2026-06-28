// Package l3tun implements the L3 tunnel — shared TLS connection with
// per-flow authentication (conntrack) and binary frame multiplexing.
// gVisor userspace TCP/IP stack runs on top.
package l3tun

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"aSuspect/spa"
	"time"
)

// ── Constants ────────────────────────────────────────────────────────────────

const (
	l3Version        = 0x05
	cmdAuthReq       = 0x13
	cmdAuthResp      = 0x93
	cmdDataReq       = 0x14
	cmdDataResp      = 0x94
	cmdHeartbeatReq  = 0x15
	cmdHeartbeatResp = 0x95
	cmdSecondVipReq  = 0x16
	cmdSecondVipResp = 0x96
	maxDataPayload   = 4096
)

// ── tunnel ───────────────────────────────────────────────────────────────────

// tunnel manages L3 connections to aTrust nodes and provides
// a raw IP packet I/O interface.  gVisor runs on top.
type tunnel struct {
	state   clientInfo
	signKey []byte

	// SpaExt is pre-computed SPA ClientHello extension data.
	// When set, TLS dials inject it into the ClientHello.
	SpaExt []byte

	conns   map[string]*conn // node address → TLS conn
	connsMu sync.Mutex
	dialing map[string]*dialWait
	closed  bool

	// Incoming packets from all connections → gVisor.
	Incoming chan []byte

	conntrack *conntrackMgr
	OnVIP     func([]net.IP)
}

type clientInfo struct {
	sid          string
	deviceID     string
	connectionID string
	username     string
}

type conn struct {
	tls     net.Conn
	reader  *bufio.Reader
	writeMu sync.Mutex
	closeCh chan struct{}
	once    sync.Once
	addr    string
}

type dialWait struct {
	done chan struct{}
	conn *conn
	err  error
}

// newTunnel creates an L3 tunnel manager.
func newTunnel(sid, deviceID, connectionID, username, signKeyHex string) (*tunnel, error) {
	signKey, err := hex.DecodeString(signKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid sign key: %w", err)
	}

	t := &tunnel{
		state: clientInfo{
			sid: sid, deviceID: deviceID,
			connectionID: connectionID, username: username,
		},
		signKey:   signKey,
		conns:     make(map[string]*conn),
		dialing:   make(map[string]*dialWait),
		Incoming:  make(chan []byte, 4096),
		conntrack: newConntrackMgr(),
	}

	// Wire up per-flow auth — DoAuth sends the frame on the active conn
	// and returns immediately; the async response is handled by
	// readLoop → handleAuthResp → markAuth.
	t.conntrack.DoAuth = func(c *conn, key string, authID uint64,
		srcIP net.IP, srcPort uint16,
		dstIP net.IP, dstPort uint16,
		proto uint8, appID string,
	) error {
		return t.sendPerFlowAuth(c, authID, srcIP, srcPort, dstIP, dstPort, proto, appID)
	}

	return t, nil
}

// EnsureConn returns a TLS connection for the given node address,
// creating one if necessary.
func (t *tunnel) EnsureConn(nodeAddr string) (*conn, error) {
	t.connsMu.Lock()
	if t.closed {
		t.connsMu.Unlock()
		return nil, fmt.Errorf("L3 tunnel closed")
	}
	if c, ok := t.conns[nodeAddr]; ok {
		t.connsMu.Unlock()
		return c, nil
	}
	if wait, ok := t.dialing[nodeAddr]; ok {
		t.connsMu.Unlock()
		<-wait.done
		return wait.conn, wait.err
	}

	wait := &dialWait{done: make(chan struct{})}
	t.dialing[nodeAddr] = wait
	t.connsMu.Unlock()

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	var rawConn net.Conn
	var err error
	if len(t.SpaExt) > 0 {
		rawConn, err = spa.DialWithSPA(nodeAddr, tlsConfig, t.SpaExt)
	} else {
		rawConn, err = tls.Dial("tcp", nodeAddr, tlsConfig)
	}
	if err != nil {
		err = fmt.Errorf("L3 TLS dial %s: %w", nodeAddr, err)
		t.finishDial(nodeAddr, wait, nil, err)
		return nil, err
	}

	c := &conn{
		tls:     rawConn,
		reader:  bufio.NewReader(rawConn),
		closeCh: make(chan struct{}),
		addr:    nodeAddr,
	}

	// tunnel-level auth.
	if err := t.authTunnel(c); err != nil {
		rawConn.Close()
		err = fmt.Errorf("L3 tunnel auth: %w", err)
		t.finishDial(nodeAddr, wait, nil, err)
		return nil, err
	}

	c = t.finishDial(nodeAddr, wait, c, nil)
	return c, nil
}

func (t *tunnel) finishDial(nodeAddr string, wait *dialWait, c *conn, err error) *conn {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.dialing[nodeAddr] == wait {
		delete(t.dialing, nodeAddr)
	}

	if err == nil && t.closed {
		c.close()
		err = fmt.Errorf("L3 tunnel closed")
		c = nil
	}

	if err == nil {
		if existing, ok := t.conns[nodeAddr]; ok {
			c.close()
			c = existing
		} else {
			t.conns[nodeAddr] = c
			go t.readLoop(c)
			go t.heartbeatLoop(c)
		}
	}

	wait.conn = c
	wait.err = err
	close(wait.done)
	return c
}

// WritePacket sends a raw IPv4 packet through the L3 tunnel for a specific flow.
func (t *tunnel) WritePacket(
	c *conn,
	srcIP net.IP, srcPort uint16,
	dstIP net.IP, dstPort uint16,
	proto uint8,
	appID string,
	packet []byte,
) error {
	// Ensure per-flow authentication (blocks until auth completes).
	token, err := t.conntrack.ensureToken(c, 4,
		srcIP, srcPort, dstIP, dstPort, proto, appID)
	if err != nil {
		return fmt.Errorf("conntrack: %w", err)
	}

	payload := buildDataFrame(token, [][]byte{packet})
	return c.writeFrame(payload)
}

// EvictConn removes a connection from the pool (called on read error).
func (t *tunnel) EvictConn(c *conn) {
	t.connsMu.Lock()
	if existing, ok := t.conns[c.addr]; ok && existing == c {
		delete(t.conns, c.addr)
	}
	t.connsMu.Unlock()
}

// Close shuts down all connections.
func (t *tunnel) Close() {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	for _, c := range t.conns {
		c.close()
	}
	t.conns = make(map[string]*conn)
}

// ── Internal: read loop ──────────────────────────────────────────────────────

func (t *tunnel) readLoop(c *conn) {
	defer c.close()
	defer t.EvictConn(c)

	for {
		header := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, header); err != nil {
			return
		}

		// Protocol response frame (53 00) — skip.
		if header[0] == 0x53 && header[1] == 0x00 {
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(c.reader, lenBuf); err != nil {
				return
			}
			plen := int(binary.BigEndian.Uint16(lenBuf))
			if _, err := io.ReadFull(c.reader, make([]byte, plen)); err != nil {
				return
			}
			continue
		}

		if header[0] != l3Version {
			continue
		}

		switch header[1] {
		case cmdDataResp:
			packets, err := readDataResp(c.reader)
			if err != nil {
				return
			}
			for _, pkt := range packets {
				select {
				case t.Incoming <- pkt:
				case <-c.closeCh:
					return
				}
			}

		case cmdHeartbeatResp:
			// Nothing to do.

		case cmdAuthResp:
			// Frame: 05 93 <status:1> <len:2> <payload>
			statusLen := make([]byte, 3)
			if _, err := io.ReadFull(c.reader, statusLen); err != nil {
				return
			}
			status := statusLen[0]
			plen := int(binary.BigEndian.Uint16(statusLen[1:3]))
			payload := make([]byte, plen)
			if plen > 0 {
				if _, err := io.ReadFull(c.reader, payload); err != nil {
					return
				}
			}
			t.handleAuthResp(status, payload)

		case cmdSecondVipResp:
			// Frame: 05 96 <status:1> <len:2> <payload>
			statusLen := make([]byte, 3)
			if _, err := io.ReadFull(c.reader, statusLen); err != nil {
				return
			}
			status := statusLen[0]
			plen := int(binary.BigEndian.Uint16(statusLen[1:3]))
			payload := make([]byte, plen)
			if plen > 0 {
				if _, err := io.ReadFull(c.reader, payload); err != nil {
					return
				}
			}
			t.handleSecondVIPResp(status, payload)

		default:
			// Skip unknown frames — read len:2 + payload.
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(c.reader, lenBuf); err != nil {
				return
			}
			plen := int(binary.BigEndian.Uint16(lenBuf))
			if plen > 0 {
				if _, err := io.ReadFull(c.reader, make([]byte, plen)); err != nil {
					return
				}
			}
		}
	}
}

func (t *tunnel) heartbeatLoop(c *conn) {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := c.writeFrame([]byte{l3Version, cmdHeartbeatReq, 0x00, 0x00}); err != nil {
				return
			}
		case <-c.closeCh:
			return
		}
	}
}

// ── Frames ───────────────────────────────────────────────────────────────────

func buildDataFrame(token string, packets [][]byte) []byte {
	tokenBytes := []byte(token)
	plen := 1 + len(tokenBytes) + 2 + 1 // token_len + token + reserved + count
	for _, pkt := range packets {
		plen += 2 + len(pkt)
	}

	buf := make([]byte, 0, plen+2)
	buf = append(buf, l3Version, cmdDataReq)
	buf = append(buf, byte(len(tokenBytes)))
	buf = append(buf, tokenBytes...)
	buf = append(buf, 0x00, 0x00)         // reserved
	buf = append(buf, byte(len(packets))) // packet count
	for _, pkt := range packets {
		lb := make([]byte, 2)
		binary.BigEndian.PutUint16(lb, uint16(len(pkt)))
		buf = append(buf, lb...)
		buf = append(buf, pkt...)
	}
	return buf
}

// readDataResp parses a data response frame body (after 05 94 header).
//
// Two modes:
//   - Length-prefixed: the first 2 bytes encode the payload length (1..4096).
//   - Token-prefixed: token_len + token + reserved:2 + count + [len:2 + data]...
func readDataResp(r *bufio.Reader) ([][]byte, error) {
	peek, err := r.Peek(2)
	if err != nil {
		return nil, err
	}
	if len(peek) < 2 {
		return nil, io.EOF
	}

	plen := int(binary.BigEndian.Uint16(peek))

	// Length-prefixed mode: reasonable single-packet size.
	if plen > 0 && plen <= maxDataPayload {
		r.Discard(2)
		buf := make([]byte, plen)
		if plen > 0 {
			if _, err := io.ReadFull(r, buf); err != nil {
				return nil, err
			}
		}
		return [][]byte{buf}, nil
	}

	// Token-prefixed mode.
	tokenLen, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	token := make([]byte, int(tokenLen))
	if tokenLen > 0 {
		if _, err := io.ReadFull(r, token); err != nil {
			return nil, err
		}
	}
	// Skip reserved 2 bytes.
	if _, err := r.Discard(2); err != nil {
		return nil, err
	}

	count, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	packets := make([][]byte, 0, count)
	for i := 0; i < int(count); i++ {
		lb := make([]byte, 2)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, err
		}
		plen := int(binary.BigEndian.Uint16(lb))
		pkt := make([]byte, plen)
		if plen > 0 {
			if _, err := io.ReadFull(r, pkt); err != nil {
				return nil, err
			}
		}
		packets = append(packets, pkt)
	}
	return packets, nil
}

// ── tunnel auth ──────────────────────────────────────────────────────────────

func (t *tunnel) authTunnel(c *conn) error {
	req, _ := json.Marshal(map[string]string{"sid": t.state.sid})

	// Wrap in 05 01 D0 ... 53 00 <len> <json> ... 05 04 00 01 ...
	wrap := []byte{l3Version, 0x01, 0xD0}
	wrap = append(wrap, 0x53, 0x00)
	lb := make([]byte, 2)
	binary.BigEndian.PutUint16(lb, uint16(len(req)))
	wrap = append(wrap, lb...)
	wrap = append(wrap, req...)
	wrap = append(wrap, 0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	if err := c.WriteRaw(wrap); err != nil {
		return fmt.Errorf("tunnel auth write: %w", err)
	}

	// Read method response: 05 D0
	method := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, method); err != nil {
		return fmt.Errorf("tunnel auth read method: %w", err)
	}
	if method[0] != l3Version || method[1] != 0xD0 {
		return fmt.Errorf("unexpected tunnel auth method: %02x %02x", method[0], method[1])
	}

	// Read 53 <status> <len> <json>
	header := make([]byte, 4)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return fmt.Errorf("tunnel auth read header: %w", err)
	}
	if header[0] != 0x53 {
		return fmt.Errorf("unexpected auth version: %02x", header[0])
	}
	status := header[1]
	plen := int(binary.BigEndian.Uint16(header[2:4]))
	payload := make([]byte, plen)
	if plen > 0 {
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return fmt.Errorf("tunnel auth read payload: %w", err)
		}
	}
	if status != 0 {
		return fmt.Errorf("tunnel auth status %d: %s", status, string(payload))
	}

	// Check JSON response for code != 0.
	if len(payload) > 0 {
		var resp struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(payload, &resp) == nil && resp.Code != 0 {
			return fmt.Errorf("tunnel auth failed: %d %s", resp.Code, resp.Message)
		}
	}

	// Read VIP: 05 04 00 <addrType> <data...>
	vipHeader := make([]byte, 4)
	if _, err := io.ReadFull(c.reader, vipHeader); err != nil {
		return fmt.Errorf("tunnel auth read VIP header: %w", err)
	}
	if vipHeader[0] == l3Version {
		addrType := vipHeader[3]
		dataLen := vipPayloadLen(addrType)
		if dataLen > 0 {
			vipData := make([]byte, dataLen)
			if _, err := io.ReadFull(c.reader, vipData); err != nil {
				return fmt.Errorf("tunnel auth read VIP data: %w", err)
			}
			if ips := parseVIP(vipData); len(ips) > 0 && t.OnVIP != nil {
				t.OnVIP(ips)
			}
		}
	}

	return nil
}

func vipPayloadLen(addrType byte) int {
	switch addrType {
	case 1:
		return 6 // IPv4 + port
	case 4:
		return 18 // IPv6 + port
	case 5:
		return 22 // IPv4 + IPv6 + port
	default:
		return 4
	}
}

func parseVIP(data []byte) []net.IP {
	switch len(data) {
	case 6:
		return []net.IP{net.IPv4(data[0], data[1], data[2], data[3])}
	case 18:
		return []net.IP{net.IP(data[:16])}
	case 22:
		return []net.IP{
			net.IPv4(data[0], data[1], data[2], data[3]),
			net.IP(data[4:20]),
		}
	}
	return nil
}

// ── Per-flow auth (request) ──────────────────────────────────────────────────

// sendPerFlowAuth builds and sends the per-flow auth request frame.
// It returns immediately after writing; the response is handled
// asynchronously by handleAuthResp → markAuth.
func (t *tunnel) sendPerFlowAuth(
	c *conn,
	authID uint64,
	srcIP net.IP, srcPort uint16,
	dstIP net.IP, dstPort uint16,
	proto uint8,
	appID string,
) error {
	protoName := protoLabel(proto)

	url := fmt.Sprintf("%s://%s:%d", protoName, dstIP, dstPort)

	procPath := "/usr/bin/aTrust"
	procName := "aTrust"
	if dstPort == 22 {
		procName = "ssh"
		procPath = "/usr/bin/ssh"
	}
	procHash := fmt.Sprintf("%X", sha256.Sum256([]byte(procPath)))

	req := map[string]interface{}{
		"sid":           t.state.sid,
		"appId":         appID,
		"url":           url,
		"deviceId":      t.state.deviceID,
		"connectionId":  t.state.connectionID,
		"userName":      t.state.username,
		"conntrackHash": authID,
		"lang":          "en-US",
		"procHash":      procHash,
		"ip": map[string]interface{}{
			"atype":    0x0800,
			"protocol": proto,
			"destAddr": dstIP.String(),
			"destPort": dstPort,
			"srcAddr":  srcIP.String(),
			"srcPort":  srcPort,
		},
		"env": map[string]interface{}{
			"application": map[string]interface{}{
				"runtime": map[string]interface{}{
					"process": map[string]string{
						"name":              procName,
						"digital_signature": "TrustAppClosed",
						"platform":          "Linux",
						"fingerprint":       procHash,
						"description":       "TrustAppClosed",
						"path":              procPath,
						"version":           "TrustAppClosed",
						"security_env":      "normal",
					},
					"process_trusted": "TRUSTED",
				},
			},
		},
		"xRequestSig": "",
	}

	unsigned, _ := json.Marshal(req)
	// Sign the FULL JSON including empty xRequestSig, then replace it.
	mac := hmac.New(sha256.New, t.signKey)
	mac.Write(unsigned)
	sig := strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))

	uns := string(unsigned)
	final := uns[:len(uns)-3] + `"` + sig + `"}`

	// Frame: 05 13 <len:2> <json>
	frame := []byte{l3Version, cmdAuthReq}
	lb := make([]byte, 2)
	binary.BigEndian.PutUint16(lb, uint16(len(final)))
	frame = append(frame, lb...)
	frame = append(frame, []byte(final)...)

	return c.writeFrame(frame)
}

// ── Per-flow auth (response) ─────────────────────────────────────────────────

// handleAuthResp processes an async per-flow auth response (0x93).
func (t *tunnel) handleAuthResp(status byte, payload []byte) {
	var resp struct {
		Code int    `json:"code"`
		Msg  string `json:"message"`
		Data struct {
			ConntrackHash uint64 `json:"conntrackHash"`
			ConnectToken  string `json:"connectToken"`
			Token         string `json:"token"`
		} `json:"data"`
	}

	if err := json.Unmarshal(payload, &resp); err != nil {
		return
	}

	// Check status byte first.
	if status != 0 {
		t.conntrack.markAuth(resp.Data.ConntrackHash, "",
			fmt.Errorf("auth status %d: %s", status, resp.Msg))
		return
	}

	if resp.Data.ConntrackHash == 0 {
		return
	}

	token := strings.TrimSpace(resp.Data.ConnectToken)
	if token == "" {
		token = strings.TrimSpace(resp.Data.Token)
	}

	var err error
	if resp.Code != 0 {
		err = fmt.Errorf("auth failed: %d %s", resp.Code, resp.Msg)
	}
	if err == nil && token == "" {
		err = fmt.Errorf("missing connect token in auth response")
	}

	t.conntrack.markAuth(resp.Data.ConntrackHash, token, err)
}

// ── Second VIP response ──────────────────────────────────────────────────────

func (t *tunnel) handleSecondVIPResp(status byte, payload []byte) {
	if status != 0 {
		return
	}
	ips := extractIPsFromSecondVIP(payload)
	if len(ips) > 0 && t.OnVIP != nil {
		t.OnVIP(ips)
	}
}

func extractIPsFromSecondVIP(payload []byte) []net.IP {
	var data interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil
	}
	return extractIPs(data)
}

func extractIPs(v interface{}) []net.IP {
	var ips []net.IP
	switch val := v.(type) {
	case map[string]interface{}:
		for _, item := range val {
			ips = append(ips, extractIPs(item)...)
		}
	case []interface{}:
		for _, item := range val {
			ips = append(ips, extractIPs(item)...)
		}
	case string:
		if ip := net.ParseIP(val); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func protoLabel(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmp6"
	default:
		return "ip"
	}
}

// ── IPv4 packet parsing ──────────────────────────────────────────────────────

// parsedPacket holds the extracted 5-tuple from a raw IPv4 packet.
type parsedPacket struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Proto   uint8 // 6=TCP, 17=UDP, 1=ICMP
}

// parseIPv4Packet extracts flow info from a raw IPv4 packet.
// Returns zero-value ports for non-TCP/UDP protocols (ICMP).
func parseIPv4Packet(raw []byte) (parsedPacket, error) {
	if len(raw) < 20 {
		return parsedPacket{}, fmt.Errorf("packet too short for IPv4 header: %d bytes", len(raw))
	}

	verIHL := raw[0]
	if verIHL>>4 != 4 {
		return parsedPacket{}, fmt.Errorf("not IPv4: version %d", verIHL>>4)
	}
	ihl := int(verIHL&0x0F) * 4
	if ihl < 20 || len(raw) < ihl {
		return parsedPacket{}, fmt.Errorf("IPv4 IHL too large: %d > %d", ihl, len(raw))
	}

	proto := raw[9]
	srcIP := net.IPv4(raw[12], raw[13], raw[14], raw[15])
	dstIP := net.IPv4(raw[16], raw[17], raw[18], raw[19])

	pp := parsedPacket{
		SrcIP: srcIP,
		DstIP: dstIP,
		Proto: proto,
	}

	// Extract ports from TCP/UDP transport header.
	if proto == 6 || proto == 17 {
		if len(raw) < ihl+4 {
			return pp, nil // truncated transport header
		}
		pp.SrcPort = binary.BigEndian.Uint16(raw[ihl : ihl+2])
		pp.DstPort = binary.BigEndian.Uint16(raw[ihl+2 : ihl+4])
	}

	return pp, nil
}

// ── Conn helpers ─────────────────────────────────────────────────────────────

func (c *conn) writeFrame(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.tls.Write(data)
	return err
}

// WriteRaw sends raw bytes directly on the TLS connection.
// Exported for DNS resolver and other direct-write paths.
func (c *conn) WriteRaw(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.tls.Write(data)
	return err
}

func (c *conn) close() {
	c.once.Do(func() {
		close(c.closeCh)
		c.tls.Close()
	})
}
