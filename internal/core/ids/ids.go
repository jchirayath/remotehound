// Package ids generates opaque identifiers and secret codes from crypto/rand
// (SEC-21). It is the only place random identifiers are made. It also owns
// ClientKey, the one definition of "the same client" every limiter uses.
package ids

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"net/netip"
)

// ClientKey identifies a client for rate and abuse limits: an IPv4 address
// (IPv4-mapped IPv6 is unmapped, so both spellings are one client), an IPv6
// address by its /64 (one customer allocation), so rotating addresses inside
// a prefix does not multiply a budget. Used by the HTTP limiter, the tunnel's
// pre-auth limiter and the enrolment miss limiter.
func ClientKey(ip string) string { return prefixKey(ip, 64, ip) }

// ClientNetKey is the wider IPv6 network a client sits in (its /48, a typical
// site allocation), for caps above the per-client one; "" for IPv4 and
// unparsable input.
func ClientNetKey(ip string) string { return prefixKey(ip, 48, "") }

func prefixKey(ip string, bits int, fallback string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return fallback
	}
	if a = a.Unmap(); a.Is4() {
		if bits == 64 {
			return a.String()
		}
		return ""
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return fallback
	}
	return p.String()
}

// idAlphabet is lower-case base32-ish without look-alikes; IDs are opaque (API-6).
const idAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// CodeAlphabet is used for enrolment codes people type by hand: no i, l, o, 0, 1.
// 31 symbols ^ 6 = 887,503,681 combinations.
const CodeAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// CodeLength is the length of an enrolment code.
const CodeLength = 6

// New returns prefix + "_" + 16 random symbols, e.g. "dev_k7q2mxp4…".
func New(prefix string) string { return prefix + "_" + randomString(idAlphabet, 16) }

// Code returns a fresh enrolment code.
func Code() string { return randomString(CodeAlphabet, CodeLength) }

// Hex returns n random bytes hex-encoded (used for keys and CSRF secrets).
func Hex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error()) // unrecoverable: no entropy
	}
	return hex.EncodeToString(b)
}

func randomString(alphabet string, n int) string {
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic("crypto/rand failed: " + err.Error())
		}
		out[i] = alphabet[v.Int64()]
	}
	return string(out)
}

// ValidCode reports whether s has the shape of an enrolment code.
func ValidCode(s string) bool {
	if len(s) != CodeLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !containsByte(CodeAlphabet, s[i]) {
			return false
		}
	}
	return true
}

func containsByte(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}
