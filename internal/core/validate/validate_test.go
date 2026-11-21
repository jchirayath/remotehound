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
