// Package ids generates opaque identifiers and secret codes from crypto/rand
// (SEC-21). It is the only place random identifiers are made.
package ids

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
)

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
