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
