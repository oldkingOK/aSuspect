package spa

import (
	"crypto/tls"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

// ExtID is the TLS extension ID for SPA data.
// Private-use range; may need adjustment to match the server's expectation.
const ExtID uint16 = 0xFDE8

// DialWithSPA opens a TLS connection with SPA extension data injected
// into the ClientHello.
func DialWithSPA(addr string, cfg *tls.Config, spaData []byte) (net.Conn, error) {
	tcpConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("spa dial tcp %s: %w", addr, err)
	}

	sni := ""
	if cfg != nil {
		sni = cfg.ServerName
	}
	if sni == "" {
		sni, _, _ = net.SplitHostPort(addr)
	}

	spec := clientHelloSpec(sni, spaData)
	uconn := utls.UClient(tcpConn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: cfg != nil && cfg.InsecureSkipVerify,
	}, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("spa: apply utls preset: %w", err)
	}
	if err := uconn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("spa: utls handshake: %w", err)
	}
	return uconn, nil
}

func clientHelloSpec(sni string, spaData []byte) utls.ClientHelloSpec {
	return utls.ClientHelloSpec{
		TLSVersMax: utls.VersionTLS13,
		TLSVersMin: utls.VersionTLS12,
		CipherSuites: []uint16{
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CompressionMethods: []uint8{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: sni},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519, utls.CurveP256, utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.PSSWithSHA256,
					utls.PSSWithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA256,
					utls.PKCS1WithSHA384,
					utls.PKCS1WithSHA512,
				},
			},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.GenericExtension{Id: ExtID, Data: spaData},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13, utls.VersionTLS12,
			}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
			}},
		},
	}
}
