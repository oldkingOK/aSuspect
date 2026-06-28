package shared

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// RandHex returns n random hex characters. Panics if crypto/rand.Read fails,
// which should never happen on a healthy system (entropy exhaustion means
// the entire TLS stack is broken anyway).
func RandHex(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("crypto/rand: %w", err))
	}
	return hex.EncodeToString(b)[:n]
}

