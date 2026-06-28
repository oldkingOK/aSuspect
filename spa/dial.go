package spa

import (
	"crypto/tls"
	"fmt"
	"net"
)

// DialTLS opens a TLS connection to addr. If spaExt is non-empty, the SPA
// ClientHello extension is injected; otherwise a standard TLS handshake is used.
func DialTLS(addr string, cfg *tls.Config, spaExt []byte) (net.Conn, error) {
	if len(spaExt) > 0 {
		conn, err := DialWithSPA(addr, cfg, spaExt)
		if err != nil {
			return nil, fmt.Errorf("spa dial %s: %w", addr, err)
		}
		return conn, nil
	}
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", addr, err)
	}
	return conn, nil
}
