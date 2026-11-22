package device

// @feature:devices

import "testing"

// Regression: a saved login "AzureAD\user@domain" or ".\admin" reached Windows as one
// username with no domain, so the automatic sign-in failed ("no such user") every time
// and the session fell back to the Windows sign-in screen. RDP carries the domain apart.
func TestSplitRDPDomain(t *testing.T) {
	cases := []struct{ user, domain, wantUser, wantDomain string }{
		{`AzureAD\grace@example.com`, "", "grace@example.com", "AzureAD"},
		{`.\avdadmin`, "", "avdadmin", "."},
		{`CORP\ada`, "", "ada", "CORP"},
		{"ada@example.com", "", "ada@example.com", ""}, // UPN: Windows resolves it itself
		{"ada", "", "ada", ""},
		{`CORP\ada`, "OTHER", `CORP\ada`, "OTHER"}, // an explicit domain option wins; leave as typed
		{`\ada`, "", `\ada`, ""},                   // nothing before the slash: not a domain
		{`CORP\`, "", `CORP\`, ""},                 // nothing after it: not a user
	}
	for _, c := range cases {
		p := map[string]string{"username": c.user}
		if c.domain != "" {
			p["domain"] = c.domain
		}
		splitRDPDomain(p)
		if p["username"] != c.wantUser || p["domain"] != c.wantDomain {
			t.Errorf("%q (domain %q): got user %q domain %q, want %q %q", c.user, c.domain, p["username"], p["domain"], c.wantUser, c.wantDomain)
		}
	}
}
