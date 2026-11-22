package ids

// @feature:enroll

import (
	"strings"
	"testing"
)

func TestCodesUseTheUnambiguousAlphabet(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		c := Code()
		if !ValidCode(c) || strings.ContainsAny(c, "il1o0") {
			t.Fatalf("bad code %q", c)
		}
		seen[c] = true
	}
	if len(seen) < 1990 {
		t.Fatalf("codes repeat too often: %d unique of 2000", len(seen))
	}
}

func TestValidCodeRejects(t *testing.T) {
	for _, c := range []string{"", "abc", "abcdefg", "ABCDEF", "abcde1", "abcdeo", "../../"} {
		if ValidCode(c) {
			t.Errorf("accepted %q", c)
		}
	}
}

func TestNewHasPrefix(t *testing.T) {
	if id := New("dev"); !strings.HasPrefix(id, "dev_") || len(id) != 20 {
		t.Fatalf("id %q", id)
	}
}

func TestClientKeyGroupsIPv6By64(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":            "203.0.113.7",
		"::ffff:203.0.113.7":     "203.0.113.7", // IPv4-mapped is the same client
		"2001:db8:1:2::1":        "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::abc": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":        "2001:db8:1:3::/64",
		"not-an-ip":              "not-an-ip",
	} {
		if got := ClientKey(in); got != want {
			t.Errorf("ClientKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClientNetKeyGroupsIPv6By48(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":        "",
		"::ffff:203.0.113.7": "",
		"2001:db8:1:2::1":    "2001:db8:1::/48",
		"2001:db8:1:ffff::1": "2001:db8:1::/48",
		"not-an-ip":          "",
	} {
		if got := ClientNetKey(in); got != want {
			t.Errorf("ClientNetKey(%q) = %q, want %q", in, got, want)
		}
	}
}
