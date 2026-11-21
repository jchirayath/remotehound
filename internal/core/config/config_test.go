package config

// @feature:settings

import (
	"os"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func base() map[string]string {
	return map[string]string{
		"RH_PUBLIC_URL": "https://rh.example.com", "RH_AUTH_MODE": "proxy", "RH_TRUSTED_PROXIES": "172.18.0.0/16",
		"RH_SECRET_KEY": strings.Repeat("ab", 32), "RH_GUAC_JSON_SECRET": strings.Repeat("cd", 16),
	}
}

func TestLoadValidConfig(t *testing.T) {
	c, err := Load(env(base()))
	if err != nil {
		t.Fatal(err)
	}
	if c.SSHAddr != ":2222" || c.TunnelPortMin != 20000 || c.GuacPublicPath != "/guacamole" || len(c.TrustedProxies) != 1 {
		t.Fatalf("defaults not applied: %+v", c)
	}
}

func TestLoadReportsEveryProblemAtOnce(t *testing.T) {
	m := base()
	m["RH_PUBLIC_URL"] = "http://insecure.example.com"
	m["RH_TUNNEL_PORT_MIN"] = "30000"
	m["RH_TUNNEL_PORT_MAX"] = "20000"
	m["RH_AUTH_MODE"] = "magic"
	_, err := Load(env(m))
	if err == nil {
		t.Fatal("invalid config accepted")
	}
	for _, want := range []string{"RH_PUBLIC_URL", "RH_TUNNEL_PORT_MAX", "RH_AUTH_MODE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}

func TestDevModeRequiresDevelopmentAndLoopback(t *testing.T) {
	m := base()
	m["RH_AUTH_MODE"] = "dev"
	if _, err := Load(env(m)); err == nil {
		t.Fatal("dev auth allowed in production")
	}
	m["RH_ENV"] = "development"
	if _, err := Load(env(m)); err == nil {
		t.Fatal("dev auth allowed on a public bind")
	}
	m["RH_HTTP_ADDR"] = "127.0.0.1:8080"
	if _, err := Load(env(m)); err != nil {
		t.Fatalf("valid dev config rejected: %v", err)
	}
}

func TestOAuthProvidersAreValidated(t *testing.T) {
	m := base()
	m["RH_AUTH_MODE"] = "oauth"
	m["RH_AUTH_PROVIDERS"] = "google,myspace,apple"
	m["RH_AUTH_GOOGLE_CLIENT_ID"] = "g"
	_, err := Load(env(m))
	if err == nil {
		t.Fatal("accepted")
	}
	for _, want := range []string{"myspace", "RH_AUTH_GOOGLE_CLIENT_SECRET", "RH_AUTH_APPLE_CLIENT_ID", "RH_AUTH_APPLE_PRIVATE_KEY_FILE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %s: %v", want, err)
		}
	}
	m["RH_AUTH_PROVIDERS"] = "entra,google"
	m["RH_AUTH_GOOGLE_CLIENT_SECRET"] = "s"
	m["RH_AUTH_ENTRA_CLIENT_ID"] = "e"
	m["RH_AUTH_ENTRA_CLIENT_SECRET_FILE"] = "/run/secrets/entra"
	m["RH_AUTH_ENTRA_TENANT"] = "contoso.onmicrosoft.com"
	c, err := Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Providers) != 2 || c.Providers[0].ID != "entra" || c.Providers[0].Tenant != "contoso.onmicrosoft.com" {
		t.Fatalf("%+v", c.Providers)
	}
}

func TestGuacPathMustMatchURL(t *testing.T) {
	m := base()
	m["RH_GUAC_URL"] = "http://guacamole:8080/"
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "RH_GUAC_PUBLIC_PATH") {
		t.Fatalf("mismatched guac path accepted: %v", err)
	}
}

// Every documented key must appear in deploy/.env.example (HELP for operators).
func TestEnvExampleListsEveryKey(t *testing.T) {
	b, err := os.ReadFile("../../../deploy/.env.example")
	if err != nil {
		t.Skip("deploy/.env.example not present yet")
	}
	for _, k := range Keys {
		if !strings.Contains(string(b), k.Name) {
			t.Errorf("%s missing from deploy/.env.example", k.Name)
		}
	}
}

// Regression (security review): tunnel listeners must not bind all interfaces by default,
// and multi-tenant Entra needs an explicit tenant allow-list.
func TestTunnelBindAndEntraTenantGuards(t *testing.T) {
	m := base()
	m["RH_TUNNEL_BIND"] = "0.0.0.0"
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "RH_TUNNEL_BIND") {
		t.Fatalf("0.0.0.0 accepted: %v", err)
	}
	m["RH_TUNNEL_BIND_ALLOW_ANY"] = "true"
	if _, err := Load(env(m)); err != nil {
		t.Fatalf("explicit opt-in refused: %v", err)
	}
	m = base()
	m["RH_AUTH_MODE"], m["RH_AUTH_PROVIDERS"] = "oauth", "entra"
	m["RH_AUTH_ENTRA_CLIENT_ID"], m["RH_AUTH_ENTRA_CLIENT_SECRET"] = "c", "s"
	for tenant, ok := range map[string]bool{"": false, "organizations": false, "consumers": false, "aaaa-bbbb": true} {
		m["RH_AUTH_ENTRA_TENANT"] = tenant
		if _, err := Load(env(m)); (err == nil) != ok {
			t.Errorf("tenant %q: err=%v", tenant, err)
		}
	}
	m["RH_AUTH_ENTRA_TENANT"], m["RH_AUTH_ENTRA_ALLOWED_TENANTS"] = "organizations", "aaaa-bbbb"
	if _, err := Load(env(m)); err != nil {
		t.Fatalf("allow-listed multi-tenant refused: %v", err)
	}
}

// @feature:services
func TestSignOutAndControlURLsValidated(t *testing.T) {
	base := map[string]string{"RH_ENV": "development", "RH_AUTH_MODE": "proxy", "RH_TRUSTED_PROXIES": "10.0.0.2/32",
		"RH_PUBLIC_URL": "https://rh.example.com"}
	load := func(extra map[string]string) error {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		_, err := Load(func(k string) (string, bool) { v, ok := m[k]; return v, ok })
		return err
	}
	for _, bad := range []map[string]string{
		{"RH_PROXY_LOGOUT_URL": "javascript:alert(1)"},
		{"RH_PROXY_LOGOUT_URL": "//evil.example.com/x"},
		{"RH_IDP_LOGOUT_URL": "http://login.example.com/logout"},
		{"RH_CONTROL_URL": "http://rh-control:9091/v1"},
		{"RH_CONTROL_URL": "rh-control:9091"},
	} {
		if err := load(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	for _, good := range []map[string]string{
		{"RH_PROXY_LOGOUT_URL": "https://sso.example.com/oauth2/sign_out?rd=x"},
		{"RH_PROXY_LOGOUT_URL": "/oauth2/sign_out"},
		{"RH_CONTROL_URL": "http://rh-control:9091"},
	} {
		if err := load(good); err != nil {
			t.Errorf("rejected %v: %v", good, err)
		}
	}
}

// @feature:services
func TestLoadControlRequiresToken(t *testing.T) {
	if _, err := LoadControl(func(string) (string, bool) { return "", false }); err == nil || !strings.Contains(err.Error(), "RH_CONTROL_TOKEN") {
		t.Fatalf("want token error, got %v", err)
	}
	c, err := LoadControl(func(k string) (string, bool) {
		if k == "RH_CONTROL_TOKEN" {
			return strings.Repeat("a", 64), true
		}
		return "", false
	})
	if err != nil || c.Listen != ":9091" || c.DockerSocket != "/var/run/docker.sock" {
		t.Fatalf("defaults: %+v %v", c, err)
	}
}
