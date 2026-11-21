package secrets

// @feature:devices

import (
	"strings"
	"testing"

	"github.com/jchirayath/remotehound/internal/core/config"
)

func TestSealOpenBindsAAD(t *testing.T) {
	s := ForTest()
	c, err := s.Seal("p@ss", "dev_1/rdp")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c, "p@ss") {
		t.Fatal("plaintext visible")
	}
	if pt, err := s.Open(c, "dev_1/rdp"); err != nil || pt != "p@ss" {
		t.Fatalf("open: %q %v", pt, err)
	}
	if _, err := s.Open(c, "dev_2/rdp"); err == nil {
		t.Fatal("ciphertext moved to another record decrypted")
	}
}

func TestSecretNeverPrints(t *testing.T) {
	s := ForTest()
	if got := s.GuacJSONKey.String(); got != "[redacted]" {
		t.Fatal(got)
	}
}

func TestRejectsBadKeys(t *testing.T) {
	if _, err := Load(&config.Config{SecretKey: "short", GuacJSONSecret: strings.Repeat("a", 32)}); err == nil {
		t.Fatal("short master key accepted")
	}
	if _, err := Load(&config.Config{SecretKey: strings.Repeat("ab", 32), GuacJSONSecret: "zz"}); err == nil {
		t.Fatal("bad guac key accepted")
	}
}

func TestDerivedKeysDiffer(t *testing.T) {
	s := ForTest()
	if string(s.SessionKey.Bytes()) == string(s.EnrollKey.Bytes()) {
		t.Fatal("purpose keys are identical")
	}
}
