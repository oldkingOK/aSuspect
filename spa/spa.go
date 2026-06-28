// Package spa implements the Single Packet Authorization (SPA) knock
// protocol used by aTrust before establishing L3/L4 tunnels.
//
// The SPA token is embedded in a TLS ClientHello extension. The server
// validates it (via ParseClientHelloResult) and opens the tunnel port.
//
// Flow:
//
//	authConfig → antiMITMAttackData.encryptedChallenge → ParseSeed → GenerateTOTP
//	                                                      → BuildClientHelloExtension
//	                                                      → injected into TLS ClientHello
//
// Two modes:
//
//	V1 (seed_len == 0 or == 16): simple TOTP + suffix
//	V2 (seed_len > 0 and != 16): SHA256(seed + UUID_prefix) + framing + suffix
//
// The TOTP window is 8 hours (28800 seconds), not the standard 30s.
package spa

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ── Constants from the real client ─────────────────────────────────────────

const (
	// Time window for TOTP: 8 hours.
	totpTimeStep = 28800
	totpDigits   = 6
)

// 36-byte prefix (a UUID string) prepended to the seed before SHA256 in V2 mode.
var spaPrefix = []byte("bd8e6db1-8a7f-4d0a-877e-ff824030a281")

// 36-byte suffix appended to every ClientHello extension.
var spaSuffix = []byte{
	'T', 'S', 'P', 'A', 0x00, 0x09, 0x12, 0x1b,
	'n', 'u', 'l', 'l', '-', 'i', 'n', 'f', 0x00,
	0x01, 0x00, 0x00, 'c', 'S', 0x82, 'c', 0x00,
	'#', 'F', '^', 0x00, 0x15, ')', 'B', 0x01,
	0x00, 0x00, 0x00,
}

// SPA TLS extension type byte.
const (
	extTypeSHA256 = 1 // V2: SHA256 hash
	extTypeString = 2 // V1: formatted string
)

// ── Seed ──────────────────────────────────────────────────────────────────

// SeedData holds the parsed SPA seed from authConfig.antiMITMAttackData.
type SeedData struct {
	Raw     string // original seed string
	Len     int    // len(raw)
	Version uint8  // parsed version number
	Key1    string // first space-separated part
	Key2    string // second space-separated part
}

// ParseSeed parses a SPA seed string.
//
// Format: "key1 key2 version" (space-separated, 3 parts).
// If not 3 parts, the entire string is treated as key1 with version=2.
func ParseSeed(raw string) *SeedData {
	s := &SeedData{Raw: raw, Len: len(raw)}

	parts := strings.SplitN(raw, " ", 3)
	if len(parts) == 3 {
		s.Key1 = parts[0]
		s.Key2 = parts[1]
		v, err := strconv.Atoi(parts[2])
		if err == nil {
			s.Version = uint8(v)
		}
	} else {
		s.Key1 = raw
		s.Version = 2
	}

	return s
}

// ── TOTP ──────────────────────────────────────────────────────────────────

// GenerateTOTP computes the time-based one-time password for this seed.
//
// Time step = (unix_seconds - epoch) / 28800  (8-hour window).
// Key derivation:
//
//	seed_len == 16 → preproc(seed) → Base32Decode → HMAC-SHA1
//	seed_len != 16 → Base32Encode(seed) → pad "=" → ToUpper → Base32Decode → HMAC-SHA1
func GenerateTOTP(s *SeedData) (string, error) {
	step := time.Now().Unix() / totpTimeStep

	var key []byte
	if s.Len == 16 {
		cleaned := preproc(s.Raw)
		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cleaned)
		if err != nil {
			return "", fmt.Errorf("spa: base32 decode 16-byte seed: %w", err)
		}
		key = decoded
	} else {
		encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(s.Raw))
		// Pad to 8-byte boundary.
		if pad := len(encoded) % 8; pad != 0 {
			encoded += strings.Repeat("=", 8-pad)
		}
		encoded = strings.ToUpper(encoded)
		decoded, err := base32.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", fmt.Errorf("spa: base32 decode variable-length seed: %w", err)
		}
		key = decoded
	}

	return computeCode(step, totpDigits, key), nil
}

// computeCode is standard TOTP: HMAC-SHA1(key, time_step_be) → truncate → mod 10^digits.
func computeCode(step int64, digits int, key []byte) string {
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(step))

	mac := hmac.New(sha1.New, key)
	mac.Write(counter)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0F
	binary := int32(hash[offset]&0x7F)<<24 |
		int32(hash[offset+1])<<16 |
		int32(hash[offset+2])<<8 |
		int32(hash[offset+3])

	mod := int32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	code := int(binary % mod)

	return fmt.Sprintf("%0*d", digits, code)
}

// ── ClientHello Extension ─────────────────────────────────────────────────

// BuildClientHelloExtension builds the TLS ClientHello extension data for SPA.
//
// It takes the TOTP string and appends the appropriate framing.
//
// V1 (seed_len == 0 or == 16):
//
//	[totp_bytes] [0x00] [0x00] [36-byte suffix]
//
// V2 (seed_len > 0 and != 16):
//
//	[input_data] [ext_len:2] [0x00] [type:1] [data_len:2] [SHA256(seed+prefix)] [36-byte suffix]
func BuildClientHelloExtension(s *SeedData, totp string, inputData []byte) []byte {
	if s.Len != 0 && s.Len != 16 {
		return buildV2(s, []byte(totp), inputData)
	}
	return buildV1([]byte(totp))
}

// buildV1: [totp] [0x00] [0x00] [36_byte_suffix]
func buildV1(totp []byte) []byte {
	buf := make([]byte, 0, len(totp)+2+len(spaSuffix))
	buf = append(buf, totp...)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, spaSuffix...)
	return buf
}

// buildV2: [input] [ext_len:2] [0x00] [type=1] [data_len:2] [SHA256(seed+prefix)] [suffix]
func buildV2(s *SeedData, totp []byte, input []byte) []byte {
	// Compute SHA256(seed + prefix).
	h := sha256.New()
	h.Write([]byte(s.Raw))
	h.Write(spaPrefix)
	hash := h.Sum(nil)

	extLen := len(hash) + 6 // type(1) + 0x00(1) + data_len(2) + ext_total_len(2)

	buf := make([]byte, 0, len(input)+extLen+len(spaSuffix))
	buf = append(buf, input...)

	// Extension total length (big-endian 2 bytes).
	buf = append(buf, byte(extLen>>8), byte(extLen))

	// Zero byte.
	buf = append(buf, 0x00)

	// Extension type: 1 = SHA256.
	buf = append(buf, extTypeSHA256)

	// Payload length (big-endian 2 bytes).
	buf = append(buf, byte(len(hash)>>8), byte(len(hash)))

	// SHA256 payload.
	buf = append(buf, hash...)

	// 36-byte suffix.
	buf = append(buf, spaSuffix...)

	return buf
}

// ── Helpers ───────────────────────────────────────────────────────────────

// preproc replaces ambiguous Base32 characters and uppercases:
//
//	0 → O, 1 → L, 8 → B, 9 → X
func preproc(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch c {
		case '0':
			b[i] = 'O'
		case '1':
			b[i] = 'L'
		case '8':
			b[i] = 'B'
		case '9':
			b[i] = 'X'
		}
	}
	return strings.ToUpper(string(b))
}
