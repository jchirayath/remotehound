// Package validate is CORE-9: the shared boundary validators.
//
// Contract: build a Collector, call the checks for each field (they record a
// FieldError with a JSON Pointer and stable code), then return c.Err() — nil
// when everything passed, else an apierr VALIDATION_FAILED listing every
// problem at once. Handlers never hand-roll field checks.
package validate

import (
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/jchirayath/remotehound/internal/core/apierr"
)

// Collector accumulates field errors.
type Collector struct{ errs []apierr.FieldError }

// Add records an error for pointer (e.g. "/name").
func (c *Collector) Add(pointer, code, detail string) {
	c.errs = append(c.errs, apierr.FieldError{Pointer: pointer, Code: code, Detail: detail})
}

// Err returns nil or a VALIDATION_FAILED error.
func (c *Collector) Err() error {
	if len(c.errs) == 0 {
		return nil
	}
	return apierr.Validation(c.errs)
}

// Required fails on blank strings.
func (c *Collector) Required(p, v string) bool {
	if strings.TrimSpace(v) == "" {
		c.Add(p, "REQUIRED", "This field is required.")
		return false
	}
	return true
}

// MaxLen fails when v is longer than n characters.
func (c *Collector) MaxLen(p, v string, n int) bool {
	if utf8.RuneCountInString(v) > n {
		c.Add(p, "TOO_LONG", "Use at most "+itoa(n)+" characters.")
		return false
	}
	return true
}

// OneOf fails when v is not in allowed (empty v passes; combine with Required).
func (c *Collector) OneOf(p, v string, allowed ...string) bool {
	if v == "" {
		return true
	}
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	c.Add(p, "NOT_ALLOWED", "Must be one of: "+strings.Join(allowed, ", ")+".")
	return false
}

// Range fails when v is outside [lo, hi].
func (c *Collector) Range(p string, v, lo, hi int) bool {
	if v < lo || v > hi {
		c.Add(p, "OUT_OF_RANGE", "Must be between "+itoa(lo)+" and "+itoa(hi)+".")
		return false
	}
	return true
}

var nameRe = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._'()-]{0,63}$`)

// Name checks a human-facing object name (device, group).
func (c *Collector) Name(p, v string) bool {
	if !c.Required(p, v) {
		return false
	}
	if !nameRe.MatchString(v) {
		c.Add(p, "INVALID_NAME", "Use letters, numbers, spaces and . _ ' ( ) - (up to 64).")
		return false
	}
	return true
}

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$`)

// HostnameOK reports whether v is a non-empty DNS-ish hostname (ASCII letters,
// digits, dots and hyphens only: safe inside a shell command).
func HostnameOK(v string) bool { return hostnameRe.MatchString(v) }

// Hostname checks a DNS-ish hostname (empty passes).
func (c *Collector) Hostname(p, v string) bool {
	if v == "" || hostnameRe.MatchString(v) {
		return true
	}
	c.Add(p, "INVALID_HOSTNAME", "Use a hostname such as rh.example.com.")
	return false
}

// publicURLRe is the ONLY shape a public URL may have: it is substituted into
// the bootstrap scripts (inside PowerShell and sh string literals) and into
// the copy-paste one-liners, so it is a strict ASCII allow-list — no quotes
// of any kind (PowerShell also treats ‘ ’ ‚ ‛ “ ” „ as quotes), no spaces,
// no %, $, `, ?, #, @ or other non-ASCII.
var publicURLRe = regexp.MustCompile(`^(https?)://[A-Za-z0-9.-]+(:([0-9]{1,5}))?(/[A-Za-z0-9._~/-]*)?$`)

// PublicURL reports whether v is an acceptable public URL: https (http only
// when allowHTTP, i.e. development), a plain host[:port] and an optional
// path from the allow-list above.
func PublicURL(v string, allowHTTP bool) bool {
	m := publicURLRe.FindStringSubmatch(v)
	if m == nil || len(v) > 2048 || (m[1] == "http" && !allowHTTP) {
		return false
	}
	if m[3] != "" {
		n := 0
		for _, d := range m[3] {
			n = n*10 + int(d-'0')
		}
		if n < 1 || n > 65535 {
			return false
		}
	}
	return true
}

// PublicURL records INVALID_URL when v is not an acceptable public URL.
func (c *Collector) PublicURL(p, v string, allowHTTP bool) bool {
	if PublicURL(v, allowHTTP) {
		return true
	}
	c.Add(p, "INVALID_URL", "Use the https address people reach RemoteHound at, e.g. https://rh.example.com (letters, digits, . - / _ ~ only).")
	return false
}

// Email checks an address (empty passes).
func (c *Collector) Email(p, v string) bool {
	if v == "" {
		return true
	}
	a, err := mail.ParseAddress(v)
	if err != nil || a.Address != v || len(v) > 254 {
		c.Add(p, "INVALID_EMAIL", "Enter an email address such as ada@example.com.")
		return false
	}
	return true
}

var tagRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Tags checks a tag list.
func (c *Collector) Tags(p string, tags []string) bool {
	if len(tags) > 20 {
		c.Add(p, "TOO_MANY", "Use at most 20 tags.")
		return false
	}
	for i, t := range tags {
		if !tagRe.MatchString(t) {
			c.Add(p+"/"+itoa(i), "INVALID_TAG", "Tags are lower-case letters, numbers and dashes (max 32).")
			return false
		}
	}
	return true
}

// ID checks an opaque id with the given prefix (empty passes).
func (c *Collector) ID(p, v, prefix string) bool {
	if v == "" {
		return true
	}
	if !strings.HasPrefix(v, prefix+"_") || len(v) > 64 {
		c.Add(p, "INVALID_ID", "Pick an existing item.")
		return false
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
