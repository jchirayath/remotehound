package guac

import (
	"mime"
	"net/http"
	"strings"
)

// FormContentType is what a form body is forwarded as, so Guacamole decodes
// exactly the bytes the gate parsed.
const FormContentType = "application/x-www-form-urlencoded; charset=UTF-8"

// IsTokensLogin reports a login request (POST <ctx>/api/tokens, exactly).
func IsTokensLogin(r *http.Request) bool {
	return r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/api/tokens") && !strings.Contains(r.URL.Path, ";")
}

// AmbiguousTokensPath reports paths a servlet container may route to the
// login resource although they are not spelled exactly like it
// ("/api/tokens/", path parameters). They are refused, never forwarded.
func AmbiguousTokensPath(r *http.Request) bool {
	p := strings.ToLower(r.URL.Path)
	return strings.HasSuffix(p, "/api/tokens/") || (strings.Contains(p, "/api/tokens") && strings.Contains(p, ";")) ||
		(strings.HasSuffix(p, "/api/tokens") && !strings.HasSuffix(r.URL.Path, "/api/tokens"))
}

// Body kinds of a request headed for Guacamole. The gate (which looks for
// token= and data=) and the proxy (which drops a stale token from a data=
// login) must agree on which bodies carry form fields, so both use BodyKind.
const (
	BodyNone    = iota // no body
	BodyForm           // application/x-www-form-urlencoded (any spelling, any parameters)
	BodyOpaque         // JSON (REST API) or octet-stream (tunnel writes, file streams): no form fields
	BodyRefused        // anything else (multipart, text, untyped, unparseable): never forwarded
)

// BodyKind classifies r's body by its media type, parsed the way a servlet
// container would (case-insensitive, parameters ignored).
func BodyKind(r *http.Request) int {
	if r.Body == nil || r.Body == http.NoBody || (r.ContentLength == 0 && len(r.TransferEncoding) == 0) {
		return BodyNone
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			return BodyNone // a GET body is never read for parameters
		}
		return BodyRefused
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return BodyRefused
	}
	switch mt {
	case "application/x-www-form-urlencoded":
		// Only a charset both sides decode identically (UTF-8 / ASCII); any
		// other charset or parameter could make Tomcat read other fields.
		for k, v := range params {
			if k != "charset" {
				return BodyRefused
			}
			switch strings.ToLower(v) {
			case "utf-8", "us-ascii":
			default:
				return BodyRefused
			}
		}
		return BodyForm
	case "application/json", "application/octet-stream":
		return BodyOpaque
	}
	return BodyRefused
}
