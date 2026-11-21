package device

// @feature:devices

import "testing"

// Regression: Guacamole decodes the client identifier as Latin-1, so a "·"
// in the connection name produced "Â·" and the session never opened.
func TestConnectionNameIsASCII(t *testing.T) {
	if got := ConnectionName("Ada’s Mac · café", "rdp"); got != "Ada_s Mac _ caf_ - RDP" {
		t.Fatalf("got %q", got)
	}
	for _, r := range ConnectionName("ünïcødé", "ssh") {
		if r > 0x7e {
			t.Fatalf("non-ASCII rune %q", r)
		}
	}
}
