// Package l4quic implements the L4 TCP tunnel — per-connection TLS + binary
// framing. Named l4quic to reserve the l4 namespace for a future QUIC upgrade.
//
// Each TCP connection opens its own TLS session to an aTrust node.
// No userspace TCP/IP stack is needed — the aTrust server handles
// TCP state on the remote side.
//
// Protocol frames (all big-endian):
//
//	Client → Server:
//	  Init:     05 01 81 53 <json_len:2> <HMAC-SHA256-signed JSON>
//	  Dest:     05 01 01 01 <ipv4:4> <port:2>           (IP)
//	           05 01 01 03 <domain_len:1> <domain> <port:2>  (domain)
//	  Data:     01 00 <len:2> <data>
//	  Close:    01 01 00 00
//
//	Server → Client:
//	  Data:     01 00 <len:2> <data>
//	  Protocol: 53 00 <json_len:2> <json>
//	  Close:    01 01 30 30
package l4quic

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"aSuspect/spa"
)

// Tunnel is the L4 TCP tunnel dialer.
type Tunnel struct {
	SID          string
	DeviceID     string
	ConnectionID string
	Username     string
	SignKey      string

	// SpaExt is pre-computed SPA ClientHello extension data.
	SpaExt []byte
}

// Conn is a single L4 TCP-tunnel stream.
type Conn struct {
	tls    net.Conn
	reader *bufio.Reader
	buf    []byte // leftover from frame parsing
}

// Dial connects to an aTrust node and opens a TCP tunnel to dst.
// If domain is non-empty, the domain-form destination frame is used.
func (t *Tunnel) Dial(nodeAddr string, dstIP net.IP, dstPort int, domain, appID string) (*Conn, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	rawConn, err := spa.DialTLS(nodeAddr, tlsConfig, t.SpaExt)
	if err != nil {
		return nil, err
	}

	// Build and send init frame.
	initFrame, err := t.buildInitFrame(dstIP, dstPort, domain, appID)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	if _, err := rawConn.Write(initFrame); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("L4 send init: %w", err)
	}

	// Build and send destination frame.
	var destFrame []byte
	if domain != "" {
		destFrame = buildDomainDestFrame(domain, dstPort)
	} else {
		destFrame = buildIPDestFrame(dstIP, dstPort)
	}
	if _, err := rawConn.Write(destFrame); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("L4 send dest: %w", err)
	}

	return &Conn{
		tls:    rawConn,
		reader: bufio.NewReader(rawConn),
	}, nil
}

// Read reads data from the L4 tunnel, handling the binary frame protocol.
func (c *Conn) Read(b []byte) (int, error) {
	// Serve leftovers first.
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}

	for {
		header := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, header); err != nil {
			return 0, err
		}

		if header[0] == 0x01 && header[1] == 0x00 {
			// Data frame.
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(c.reader, lenBuf); err != nil {
				return 0, err
			}
			dlen := binary.BigEndian.Uint16(lenBuf)
			data := make([]byte, dlen)
			if _, err := io.ReadFull(c.reader, data); err != nil {
				return 0, err
			}

			n := copy(b, data)
			if n < len(data) {
				c.buf = data[n:]
			}
			return n, nil
		} else if header[0] == 0x01 && header[1] == 0x01 {
			// Close frame from server — must be 30 30.
			header = make([]byte, 2)
			if _, err := io.ReadFull(c.reader, header); err != nil {
				return 0, err
			}
			if header[0] == 0x30 && header[1] == 0x30 {
				c.tls.Close()
				return 0, fmt.Errorf("L4: connection closed by server")
			}
		} else if header[0] == 0x53 && header[1] == 0x00 {
			// Protocol response.
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(c.reader, lenBuf); err != nil {
				return 0, err
			}
			plen := binary.BigEndian.Uint16(lenBuf)
			payload := make([]byte, plen)
			if _, err := io.ReadFull(c.reader, payload); err != nil {
				return 0, err
			}

			if !strings.Contains(string(payload), "OK") {
				c.tls.Close()
				return 0, fmt.Errorf("L4 protocol error: %s", string(payload))
			}
			// OK — loop to next frame.
		}
	}
}

// Write sends data through the L4 tunnel wrapped in a data frame.
func (c *Conn) Write(b []byte) (int, error) {
	if len(b) > 0xFFFF {
		return 0, fmt.Errorf("L4 data too large: %d", len(b))
	}

	frame := []byte{0x01, 0x00}
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(b)))
	frame = append(frame, lenBuf...)
	frame = append(frame, b...)

	if _, err := c.tls.Write(frame); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close sends the close frame and shuts down the TLS connection.
func (c *Conn) Close() error {
	c.tls.Write([]byte{0x01, 0x01, 0x00, 0x00})
	return c.tls.Close()
}

// ── Frame builders ──────────────────────────────────────────────────────────

func (t *Tunnel) buildInitFrame(dstIP net.IP, dstPort int, domain, appID string) ([]byte, error) {
	destAddr := fmt.Sprintf("%s:%d", dstIP, dstPort)
	if domain != "" {
		destAddr = fmt.Sprintf("%s:%d", domain, dstPort)
	}

	procName := "google-chrome-stable"
	procPath := "/usr/bin/google-chrome-stable"
	if dstPort == 22 {
		procName = "ssh"
		procPath = "/usr/bin/ssh"
	}
	procHash := fmt.Sprintf("%X", sha256.Sum256([]byte(procPath)))

	msg := fmt.Sprintf(
		`{"sid":"%s","appId":"%s","url":"tcp://%s","deviceId":"%s","connectionId":"%s","procHash":"%s","userName":"%s","rcAppliedInfo":0,"lang":"en-US","destAddr":"%s","env":{"application":{"runtime":{"process":{"name":"%s","digital_signature":"TrustAppClosed","platform":"Linux","fingerprint":"%s","description":"TrustAppClosed","path":"%s","version":"TrustAppClosed","security_env":"normal"},"process_trusted":"TRUSTED"}}},"xRequestSig":""}`,
		t.SID, appID, destAddr, t.DeviceID, t.ConnectionID, procHash, t.Username, destAddr, procName, procHash, procPath,
	)

	signKey, err := hex.DecodeString(t.SignKey)
	if err != nil {
		return nil, fmt.Errorf("invalid sign key: %w", err)
	}
	mac := hmac.New(sha256.New, signKey)
	mac.Write([]byte(msg))
	sig := strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))
	msg = msg[:len(msg)-3] + `"` + sig + `"}`

	msgBytes := []byte(msg)
	mlen := make([]byte, 2)
	binary.BigEndian.PutUint16(mlen, uint16(len(msgBytes)))

	frame := []byte{0x05, 0x01, 0x81, 0x53, 0x03}
	frame = append(frame, mlen...)
	frame = append(frame, msgBytes...)
	return frame, nil
}

func buildIPDestFrame(ip net.IP, port int) []byte {
	ip4 := ip.To4()
	frame := []byte{0x05, 0x01, 0x01, 0x01}
	frame = append(frame, ip4...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(port))
	frame = append(frame, portBuf...)
	return frame
}

func buildDomainDestFrame(domain string, port int) []byte {
	frame := []byte{0x05, 0x01, 0x01, 0x03}
	frame = append(frame, byte(len(domain)))
	frame = append(frame, []byte(domain)...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(port))
	frame = append(frame, portBuf...)
	return frame
}

// LocalAddr returns the local address of the underlying TLS connection.
func (c *Conn) LocalAddr() net.Addr { return c.tls.LocalAddr() }

// RemoteAddr returns the remote address of the underlying TLS connection.
func (c *Conn) RemoteAddr() net.Addr { return c.tls.RemoteAddr() }

// SetDeadline sets the read and write deadlines.
func (c *Conn) SetDeadline(t time.Time) error { return c.tls.SetDeadline(t) }

// SetReadDeadline sets the read deadline.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.tls.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.tls.SetWriteDeadline(t) }
