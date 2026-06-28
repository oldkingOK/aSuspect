package shared

import (
	"crypto/tls"
	"net/http"
)

// NewTransport returns an http.Transport configured for aTrust servers
// (TLS with InsecureSkipVerify). Callers are responsible for attaching
// their own CookieJar or other client-level configuration.
func NewTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}
