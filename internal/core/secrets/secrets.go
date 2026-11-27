// Package secrets is CORE-2: the only code that loads secret material.
//
// Contract: Load(cfg) resolves every secret from its env value or *_FILE path
// (Docker/Kubernetes secrets), validates its shape, and keeps it in memory.
// Values are never logged: Secret.String() returns "[redacted]". Purpose-bound
// sub-keys are derived from the master key with HKDF-SHA256 so one leaked
// sub-key cannot be used for another purpose (CRY-*).
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jchirayath/remotehound/internal/core/config"
)

// Secret wraps a value so it cannot be printed by accident.
type Secret struct{ v []byte }

// String implements fmt.Stringer without revealing the value.
func (Secret) String() string { return "[redacted]" }

// GoString implements fmt.GoStringer without revealing the value.
func (Secret) GoString() string { return "[redacted]" }

// Bytes returns the raw value. Call sites must not log it.
func (s Secret) Bytes() []byte { return s.v }

// Empty reports whether no value is set.
func (s Secret) Empty() bool { return len(s.v) == 0 }

// Set is every secret the process uses.
type Set struct {
	master      []byte
	GuacJSONKey Secret // 16 bytes (AES-128), shared with Guacamole
	ProxySecret Secret
	// ControlToken authenticates remotehound to rh-control (empty = control off).
	ControlToken Secret
	providers    map[string]providerSecret
	SessionKey   Secret // HMAC key for session and OIDC state cookies
	EnrollKey    Secret // HMAC key for enrollment code hashes
	sealer       cipher.AEAD
}

// Load resolves secrets per cfg. In development, a missing master key or
// Guacamole key is generated once and stored under the data dir (0600).
func Load(cfg *config.Config) (*Set, error) {
	masterHex, err := resolve(cfg.SecretKey, cfg.SecretKeyFile)
	if err != nil {
		return nil, fmt.Errorf("RH_SECRET_KEY: %w", err)
	}
	if masterHex == "" && cfg.Development() {
		if masterHex, err = devGenerated(filepath.Join(cfg.DataDir, "dev-secret-key"), 32); err != nil {
			return nil, err
		}
	}
	master, err := hex.DecodeString(masterHex)
	if err != nil || len(master) != 32 {
		return nil, errors.New("RH_SECRET_KEY: must be 64 hex characters (32 bytes); generate with `remotehound gen-secret`")
	}

	guacHex, err := resolve(cfg.GuacJSONSecret, cfg.GuacJSONSecretFile)
	if err != nil {
		return nil, fmt.Errorf("RH_GUAC_JSON_SECRET: %w", err)
	}
	if guacHex == "" && cfg.Development() {
		if guacHex, err = devGenerated(filepath.Join(cfg.DataDir, "dev-guac-json-secret"), 16); err != nil {
			return nil, err
		}
	}
	guac, err := hex.DecodeString(guacHex)
	if err != nil || len(guac) != 16 {
		return nil, errors.New("RH_GUAC_JSON_SECRET: must be 32 hex characters (128-bit), identical to guacamole's JSON_SECRET_KEY")
	}

	ctl, err := ControlToken(cfg.ControlToken, cfg.ControlTokenFile)
	if err != nil {
		return nil, err
	}
	if cfg.ControlURL != "" && ctl.Empty() {
		return nil, errors.New("RH_CONTROL_TOKEN: required when RH_CONTROL_URL is set (the same value rh-control has)")
	}

	s := &Set{
		master:       master,
		GuacJSONKey:  Secret{guac},
		ProxySecret:  Secret{[]byte(cfg.ProxySecret)},
		ControlToken: ctl,
		providers:    map[string]providerSecret{},
	}
	for _, p := range cfg.Providers {
		name := "RH_AUTH_" + strings.ToUpper(p.ID)
		cs, err := resolve(p.ClientSecret, p.ClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("%s_CLIENT_SECRET: %w", name, err)
		}
		ps := providerSecret{clientSecret: Secret{[]byte(cs)}}
		if p.PrivateKeyFile != "" {
			b, err := os.ReadFile(p.PrivateKeyFile) // #nosec G304 -- operator-supplied secret path
			if err != nil {
				return nil, fmt.Errorf("%s_PRIVATE_KEY_FILE: %w", name, err)
			}
			ps.privateKey = Secret{b}
		}
		s.providers[p.ID] = ps
	}
	if s.SessionKey.v, err = s.derive("remotehound/session/v1", 32); err != nil {
		return nil, err
	}
	if s.EnrollKey.v, err = s.derive("remotehound/enroll/v1", 32); err != nil {
		return nil, err
	}
	sealKey, err := s.derive("remotehound/seal/v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sealKey)
	if err != nil {
		return nil, err
	}
	if s.sealer, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}
	return s, nil
}

type providerSecret struct{ clientSecret, privateKey Secret }

// ControlToken resolves the remotehound ⇄ rh-control shared token. Empty is
// allowed (control disabled); a set token must be at least 32 characters so a
// guessable value cannot unlock the Docker-socket helper.
func ControlToken(value, file string) (Secret, error) {
	v, err := resolve(value, file)
	if err != nil {
		return Secret{}, fmt.Errorf("RH_CONTROL_TOKEN: %w", err)
	}
	if v != "" && len(v) < 32 {
		return Secret{}, errors.New("RH_CONTROL_TOKEN: must be at least 32 characters; generate with `remotehound gen-secret`")
	}
	return Secret{[]byte(v)}, nil
}

// Provider returns a sign-in provider's client secret and (Apple) private key PEM.
func (s *Set) Provider(id string) (clientSecret string, privateKeyPEM []byte) {
	p := s.providers[id]
	return string(p.clientSecret.Bytes()), p.privateKey.Bytes()
}

// ForTest builds a Set from fixed keys (tests only).
func ForTest() *Set {
	cfg := &config.Config{
		SecretKey:      strings.Repeat("ab", 32),
		GuacJSONSecret: "4c0b569e4c96df157eee1b65dd0e4d41",
	}
	s, err := Load(cfg)
	if err != nil {
		panic(err)
	}
	return s
}

func (s *Set) derive(label string, n int) ([]byte, error) {
	return hkdf.Key(sha256.New, s.master, nil, label, n)
}

// Seal encrypts plaintext with AES-256-GCM; aad binds it to its owner (e.g.
// the device ID + service kind) so ciphertext cannot be moved between records.
func (s *Set) Seal(plaintext, aad string) (string, error) {
	nonce := make([]byte, s.sealer.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := s.sealer.Seal(nonce, nonce, []byte(plaintext), []byte(aad))
	return "v1:" + base64.RawStdEncoding.EncodeToString(out), nil
}

// Open reverses Seal.
func (s *Set) Open(sealed, aad string) (string, error) {
	raw, ok := strings.CutPrefix(sealed, "v1:")
	if !ok {
		return "", errors.New("unknown sealed format")
	}
	b, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil || len(b) < s.sealer.NonceSize() {
		return "", errors.New("malformed sealed value")
	}
	pt, err := s.sealer.Open(nil, b[:s.sealer.NonceSize()], b[s.sealer.NonceSize():], []byte(aad))
	if err != nil {
		return "", errors.New("sealed value failed authentication")
	}
	return string(pt), nil
}

func resolve(value, file string) (string, error) {
	if value != "" && file != "" {
		return "", errors.New("set the value or the _FILE form, not both")
	}
	if file == "" {
		return strings.TrimSpace(value), nil
	}
	b, err := os.ReadFile(file) // #nosec G304 -- operator-supplied secret path
	if err != nil {
		return "", fmt.Errorf("reading secret file: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func devGenerated(path string, n int) (string, error) {
	if b, err := os.ReadFile(path); err == nil { // #nosec G304 -- fixed path under the data dir
		return strings.TrimSpace(string(b)), nil
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	v := hex.EncodeToString(buf)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	return v, os.WriteFile(path, []byte(v+"\n"), 0o600)
}

// GenerateHex returns n random bytes hex-encoded, for `remotehound gen-secret`.
func GenerateHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
