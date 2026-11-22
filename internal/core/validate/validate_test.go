package validate

// @feature:devices

import (
	"strings"
	"testing"

	"github.com/jchirayath/remotehound/internal/core/apierr"
)

func TestCollectsAllErrors(t *testing.T) {
	var c Collector
	c.Name("/name", "")
	c.Email("/email", "not-an-email")
	c.Range("/ttl", 2, 5, 10)
	c.Tags("/tags", []string{"Bad Tag"})
	err := c.Err()
	e := apierr.As(err)
	if e.Code != apierr.CodeValidation || len(e.Fields) != 4 {
		t.Fatalf("got %+v", e)
	}
}

func TestNameRules(t *testing.T) {
	for name, ok := range map[string]bool{"laptop1": true, "Ada's Mac (work)": true, "<script>": false, strings.Repeat("a", 65): false, " lead": false} {
		var c Collector
		if got := c.Name("/n", name); got != ok {
			t.Errorf("%q: got %v", name, got)
		}
	}
}

// badPublicURLs are values that must never reach a bootstrap script or a
// copy-paste one-liner: PowerShell treats ‘ ’ ‚ ‛ as single quotes and “ ” „
// as double quotes, so any of them can close the quoted $BaseUrl string.
var badPublicURLs = []string{
	"https://rh.example.com/‘", "https://rh.example.com/’", "https://rh.example.com/‚", "https://rh.example.com/‛",
	"https://rh.example.com/“", "https://rh.example.com/”", "https://rh.example.com/„",
	"https://rh.example.com/'; iex x; '", `https://rh.example.com/"`, "https://rh.example.com/a b", "https://rh.ex ample.com",
	"https://rh.exämple.com", "https://rh.example.com/é", "https://rh.example.com/‮", "https://rh.example.com/$(id)",
	"https://rh.example.com/`id`", "https://rh.example.com/?q=1", "https://rh.example.com/#f", "https://u:p@rh.example.com",
	"https://rh.example.com:123456", "https://rh.example.com/%27", "https://rh.example.com\n", "ftp://rh.example.com",
	"rh.example.com", "https://", "http://rh.example.com",
}

func TestPublicURL(t *testing.T) {
	for _, u := range badPublicURLs {
		if PublicURL(u, false) {
			t.Errorf("accepted %q", u)
		}
		var c Collector
		if c.PublicURL("/public_url", u, false) || c.Err() == nil {
			t.Errorf("collector accepted %q", u)
		}
	}
	for _, u := range []string{"https://rh.example.com", "https://rh.example.com/", "https://rh.example.com:8443/remote-hound/x_y.z~",
		"https://127.0.0.1"} {
		if !PublicURL(u, false) {
			t.Errorf("rejected %q", u)
		}
	}
	if !PublicURL("http://127.0.0.1:8080", true) || PublicURL("http://127.0.0.1:8080", false) {
		t.Error("http must need allowHTTP")
	}
}
