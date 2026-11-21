// @feature:devices
package device

import (
	"strings"
	"testing"

	"github.com/jchirayath/remotehound/internal/model"
)

func dev(id, name, os, host string) *model.Device {
	return &model.Device{Meta: model.Meta{ID: id}, Name: name, OS: os, Hostname: host}
}

func TestNameOSMismatch(t *testing.T) {
	for _, c := range []struct {
		name, os string
		warn     bool
	}{
		{"office-linux", "macos", true}, // the real case: a Linux code run on a Mac
		{"office-linux", "linux", false},
		{"this-mac", "macos", false},
		{"Ada's MacBook", "windows", true},
		{"avd-windows", "windows", false},
		{"office-pc", "linux", false},      // names no OS: nothing to compare
		{"office-linux", "unknown", false}, // machine did not say
		{"machine", "macos", false},        // "mac" only as a whole word
	} {
		w := nameOSWarning(dev("d", c.name, c.os, "h"))
		if (w != nil) != c.warn {
			t.Errorf("%q on %s: warning=%v, want %v", c.name, c.os, w != nil, c.warn)
		}
	}
	w := nameOSWarning(dev("d", "office-linux", "macos", "Adas-Mac-Studio"))
	if !strings.Contains(w.Message, "Linux") || !strings.Contains(w.Message, "macOS") || !strings.Contains(w.Message, "Adas-Mac-Studio") {
		t.Fatalf("message: %s", w.Message)
	}
}

func TestDuplicateHost(t *testing.T) {
	a := dev("a", "studio", "macos", "Adas-Mac-Studio.local")
	b := dev("b", "office-linux", "macos", "adas-mac-studio")
	c := dev("c", "box", "linux", "adas-mac-studio") // same name, other OS: a different machine
	got := identityWarnings(a, []*model.Device{a, b, c})
	if len(got) != 1 || got[0].Code != "DUPLICATE_HOST" || got[0].OtherDeviceID != "b" {
		t.Fatalf("got %+v", got)
	}
	if w := identityWarnings(c, []*model.Device{a, b, c}); len(w) != 0 {
		t.Fatalf("different OS must not count: %+v", w)
	}
	if w := identityWarnings(dev("x", "x", "linux", "localhost"), []*model.Device{dev("y", "y", "linux", "localhost")}); len(w) != 0 {
		t.Fatalf("placeholder hostnames must not count: %+v", w)
	}
}
