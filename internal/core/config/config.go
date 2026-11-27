// Package config is CORE-1: the ONLY place the process environment is read.
//
// Contract: Load() reads every RH_* key listed in Keys, validates it, and
// returns a typed Config or an error that names every bad key at once (fail
// fast at boot). Keys documents itself: `remotehound config-doc` prints the
// table and a unit test checks deploy/.env.example lists every key.
//
// Infrastructure settings live here and need a restart. Behavior settings
// (enrollment TTL, recording, role mapping, …) are runtime settings in the
// store, edited from the UI — see docs/ARCHITECTURE.md §3.6.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/jchirayath/remotehound/internal/core/validate"
)

// Key documents one environment variable.
type Key struct {
	Name     string
	Default  string
	Secret   bool
	Required string // "", "always", or a condition in words
	Help     string
}

// Keys is the complete, documented list of environment variables.
var Keys = []Key{
	{Name: "RH_ENV", Default: "production", Help: "production | development. Development enables RH_AUTH_MODE=dev on loopback only."},
	{Name: "RH_HTTP_ADDR", Default: ":8080", Help: "Listen address for the UI, API and Guacamole proxy (plain HTTP; put TLS in front)."},
	{Name: "RH_METRICS_ADDR", Default: "127.0.0.1:9090", Help: "Internal listener for /metrics (Prometheus) and, if enabled, pprof. Never publish it."},
	{Name: "RH_SSH_ADDR", Default: ":2222", Help: "Listen address of the embedded SSH tunnel server devices connect to."},
	{Name: "RH_SSH_PUBLIC_PORT", Default: "2222", Help: "Port devices dial (as published on the host). Initial value for the ssh_public_port setting."},
	{Name: "RH_TUNNEL_BIND", Default: "127.0.0.1", Help: "Address tunnel listeners bind on (a device's raw RDP/SSH/VNC). Must be reachable by guacd and nothing else: the bundle uses remotehound's address on the internal guac network."},
	{Name: "RH_TUNNEL_BIND_ALLOW_ANY", Default: "false", Help: "Set true to allow binding tunnel listeners on 0.0.0.0/:: (exposes every device's desktop to anything that reaches the host — only behind a firewall you control)."},
	{Name: "RH_TUNNEL_ADVERTISE_HOST", Default: "remotehound", Help: "Hostname guacd uses to reach tunnel listeners (the container name in the bundle)."},
	{Name: "RH_TUNNEL_PORT_MIN", Default: "20000", Help: "First port of the tunnel listener range."},
	{Name: "RH_TUNNEL_PORT_MAX", Default: "20999", Help: "Last port of the tunnel listener range (inclusive)."},
	{Name: "RH_DATA_DIR", Default: "/data", Help: "State, audit log, SSH host key and backups. Back this volume up."},
	{Name: "RH_RECORDINGS_DIR", Default: "/recordings", Help: "Where guacd writes session recordings (mounted read-only into remotehound)."},
	{Name: "RH_GUAC_RECORDING_PATH", Default: "/recordings", Help: "The same directory as guacd sees it (recording-path parameter)."},
	{Name: "RH_BUNDLE_LOG", Default: "", Help: "Optional JSONL file of container logs written by the vector profile; shown as source=bundle in Logs."},
	{Name: "RH_PUBLIC_URL", Default: "", Required: "always", Help: "External https URL of RemoteHound, e.g. https://rh.example.com. Initial value for the public_url setting."},
	{Name: "RH_AUTH_MODE", Default: "oauth", Help: "oauth (sign in with the providers in RH_AUTH_PROVIDERS) | proxy (trusted authenticating proxy) | dev (loopback development only)."},
	{Name: "RH_AUTH_PROVIDERS", Default: "", Required: "when RH_AUTH_MODE=oauth", Help: "Comma-separated sign-in providers, shown in this order: entra, google, apple, facebook, github, oidc."},
	{Name: "RH_PROXY_EMAIL_HEADER", Default: "X-Forwarded-Email", Help: "proxy mode: header carrying the authenticated user's email."},
	{Name: "RH_PROXY_NAME_HEADER", Default: "X-Forwarded-User", Help: "proxy mode: header carrying the display name / user."},
	{Name: "RH_PROXY_GROUPS_HEADER", Default: "X-Forwarded-Groups", Help: "proxy mode: comma-separated groups (mapped through the roles_map setting)."},
	{Name: "RH_PROXY_SUBJECT_HEADER", Default: "", Help: "proxy mode, optional: header carrying the IdP's stable subject (e.g. X-Auth-Request-User from oauth2-proxy). When set, it is the identity key and the email header is for display and first-time matching only, so an email change or reuse at the IdP cannot move an account. Empty = identity keyed on the email header. On first sign-in after enabling it, a user's existing email-keyed proxy identity is converted to the subject."},
	{Name: "RH_TRUSTED_PROXIES", Default: "", Help: "Comma-separated CIDRs allowed to set X-Forwarded-For and (proxy mode) identity headers, e.g. 172.18.0.0/16."},
	{Name: "RH_PROXY_SECRET", Secret: true, Required: "when RH_AUTH_MODE=proxy", Help: "proxy mode: value the proxy must send in X-RemoteHound-Proxy-Secret on every request (generate with: remotehound gen-secret). Required: a trusted CIDR alone would admit anything else on that network."},
	{Name: "RH_PROXY_LOGOUT_URL", Default: "", Help: "proxy mode, optional: where Sign out sends the browser so the PROXY's session ends too, e.g. https://sso.example.com/oauth2/sign_out?rd=https%3A%2F%2Frh.example.com%2Fsigned-out. Without it Sign out only ends RemoteHound's session and the proxy signs you straight back in."},
	{Name: "RH_PROJECT_URL", Default: "https://github.com/jchirayath/remotehound", Help: "Where Overview's \"Learn more about RemoteHound\" link goes: the project site, or your own page about this install."},
	{Name: "RH_IDP_LOGOUT_URL", Default: "", Help: "Optional: identity provider sign-out page offered on the signed-out screen (e.g. https://login.microsoftonline.com/common/oauth2/v2.0/logout), for shared computers."},
	{Name: "RH_CONTROL_URL", Default: "", Help: "Optional: internal URL of the rh-control helper (e.g. http://rh-control:9091). Enables start/stop/restart and container logs on the Services screen. Empty = status only."},
	{Name: "RH_CONTROL_TOKEN", Secret: true, Help: "Shared token between remotehound and rh-control (64 hex chars; remotehound gen-secret prints one). Or RH_CONTROL_TOKEN_FILE."},
	{Name: "RH_CONTROL_TOKEN_FILE", Help: "File holding RH_CONTROL_TOKEN."},
	{Name: "RH_CONTROL_LISTEN", Default: ":9091", Help: "rh-control only: listen address. Put it on a network only remotehound can reach; never publish it."},
	{Name: "RH_CONTROL_DOCKER_SOCKET", Default: "/var/run/docker.sock", Help: "rh-control only: path of the Docker Engine socket mounted into the helper."},
	{Name: "RH_BOOTSTRAP_ADMIN", Default: "", Help: "Email that becomes admin on first sign-in while no admin exists."},
	{Name: "RH_SECRET_KEY", Secret: true, Help: "64 hex chars (32 bytes): master key for session signing and credential sealing. Or RH_SECRET_KEY_FILE."},
	{Name: "RH_SECRET_KEY_FILE", Help: "File holding RH_SECRET_KEY."},
	{Name: "RH_GUAC_URL", Default: "http://guacamole:8080/guacamole", Help: "Internal URL of the Guacamole web app."},
	{Name: "RH_GUAC_PUBLIC_PATH", Default: "/guacamole", Help: "Path under RH_PUBLIC_URL where RemoteHound proxies Guacamole. Must equal the path of RH_GUAC_URL."},
	{Name: "RH_GUAC_JSON_SECRET", Secret: true, Help: "32 hex chars: the JSON_SECRET_KEY given to the guacamole container. Or RH_GUAC_JSON_SECRET_FILE."},
	{Name: "RH_GUAC_JSON_SECRET_FILE", Help: "File holding RH_GUAC_JSON_SECRET."},
	{Name: "RH_GUACD_ADDR", Default: "guacd:4822", Help: "guacd host:port, used by integration checks."},
	{Name: "RH_LOG_LEVEL", Default: "INFO", Help: "Initial log level; change it at runtime on the Debug screen."},
	{Name: "RH_DEBUG_PPROF", Default: "false", Help: "Expose net/http/pprof on RH_METRICS_ADDR. Off in production unless you are debugging."},
	{Name: "RH_VERSION", Default: "", Help: "Overrides the reported service.version (set by the image build)."},
}

// ProviderIDs are the supported sign-in providers.
var ProviderIDs = []string{"entra", "google", "apple", "facebook", "github", "oidc"}

// providerKeys documents RH_AUTH_<ID>_<FIELD> for every provider.
var providerKeys = []struct {
	field, help string
	secret      bool
	only        []string
}{
	{field: "CLIENT_ID", help: "client / application ID"},
	{field: "CLIENT_SECRET", help: "client secret (or use _CLIENT_SECRET_FILE)", secret: true, only: []string{"entra", "google", "facebook", "github", "oidc"}},
	{field: "CLIENT_SECRET_FILE", help: "file holding the client secret", only: []string{"entra", "google", "facebook", "github", "oidc"}},
	{field: "SCOPES", help: "override the default scopes (space-separated)"},
	{field: "TENANT", help: "REQUIRED: your directory (tenant) ID; or organizations / common for multi-tenant (then ALLOWED_TENANTS is required)", only: []string{"entra"}},
	{field: "ALLOWED_TENANTS", help: "multi-tenant only: comma-separated tenant IDs whose users may sign in (any other tenant is refused)", only: []string{"entra"}},
	{field: "TRUST_EMAIL", help: "true if emails from this issuer are verified by you (single-tenant directory) even without email_verified", only: []string{"entra", "oidc"}},
	{field: "ISSUER", help: "issuer URL (https), e.g. https://keycloak.example.com/realms/main", only: []string{"oidc"}},
	{field: "NAME", help: "button label on the login page", only: []string{"oidc"}},
	{field: "TEAM_ID", help: "Apple developer team ID", only: []string{"apple"}},
	{field: "KEY_ID", help: "Apple Sign in with Apple key ID", only: []string{"apple"}},
	{field: "PRIVATE_KEY_FILE", help: "path to the Apple .p8 private key", only: []string{"apple"}},
}

func init() {
	for _, id := range ProviderIDs {
		for _, pk := range providerKeys {
			if pk.only != nil && !contains(pk.only, id) {
				continue
			}
			Keys = append(Keys, Key{Name: "RH_AUTH_" + strings.ToUpper(id) + "_" + pk.field, Secret: pk.secret,
				Help: id + ": " + pk.help + "."})
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// ProviderConfig is one configured sign-in provider (secrets resolved by core/secrets).
type ProviderConfig struct {
	ID               string
	ClientID         string
	ClientSecret     string
	ClientSecretFile string
	Scopes           []string
	Tenant           string
	AllowedTenants   []string
	TrustEmail       bool
	Issuer           string
	DisplayName      string
	TeamID           string
	KeyID            string
	PrivateKeyFile   string
}

// Config is the validated, typed result of Load.
type Config struct {
	Env                 string
	HTTPAddr            string
	MetricsAddr         string
	SSHAddr             string
	SSHPublicPort       int
	TunnelBind          string
	TunnelAdvertiseHost string
	TunnelPortMin       int
	TunnelPortMax       int
	DataDir             string
	RecordingsDir       string
	GuacRecordingPath   string
	BundleLog           string
	PublicURL           *url.URL
	AuthMode            string
	Providers           []ProviderConfig
	ProxyEmailHeader    string
	ProxyNameHeader     string
	ProxyGroupsHeader   string
	ProxySubjectHeader  string
	TrustedProxies      []netip.Prefix
	ProxySecret         string
	ProxyLogoutURL      string
	IdPLogoutURL        string
	ProjectURL          string
	ControlURL          string
	ControlToken        string
	ControlTokenFile    string
	BootstrapAdmin      string
	SecretKey           string
	SecretKeyFile       string
	GuacURL             *url.URL
	GuacPublicPath      string
	GuacJSONSecret      string
	GuacJSONSecretFile  string
	GuacdAddr           string
	LogLevel            string
	DebugPprof          bool
	Version             string
}

// Development reports whether the process runs in development mode.
func (c *Config) Development() bool { return c.Env == "development" }

// Load reads and validates the environment. lookup is os.LookupEnv in
// production and a map in tests.
func Load(lookup func(string) (string, bool)) (*Config, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	get := func(name string) string {
		if v, ok := lookup(name); ok {
			return strings.TrimSpace(v)
		}
		for _, k := range Keys {
			if k.Name == name {
				return k.Default
			}
		}
		return ""
	}
	var errs []string
	bad := func(name, why string) { errs = append(errs, name+": "+why) }
	atoi := func(name string, lo, hi int) int {
		v, err := strconv.Atoi(get(name))
		if err != nil || v < lo || v > hi {
			bad(name, fmt.Sprintf("must be an integer between %d and %d", lo, hi))
		}
		return v
	}

	c := &Config{
		Env:                 get("RH_ENV"),
		HTTPAddr:            get("RH_HTTP_ADDR"),
		MetricsAddr:         get("RH_METRICS_ADDR"),
		SSHAddr:             get("RH_SSH_ADDR"),
		TunnelBind:          get("RH_TUNNEL_BIND"),
		TunnelAdvertiseHost: get("RH_TUNNEL_ADVERTISE_HOST"),
		DataDir:             get("RH_DATA_DIR"),
		RecordingsDir:       get("RH_RECORDINGS_DIR"),
		GuacRecordingPath:   get("RH_GUAC_RECORDING_PATH"),
		BundleLog:           get("RH_BUNDLE_LOG"),
		AuthMode:            get("RH_AUTH_MODE"),
		ProxyEmailHeader:    get("RH_PROXY_EMAIL_HEADER"),
		ProxyNameHeader:     get("RH_PROXY_NAME_HEADER"),
		ProxyGroupsHeader:   get("RH_PROXY_GROUPS_HEADER"),
		ProxySubjectHeader:  get("RH_PROXY_SUBJECT_HEADER"),
		ProxySecret:         get("RH_PROXY_SECRET"),
		ProxyLogoutURL:      get("RH_PROXY_LOGOUT_URL"),
		IdPLogoutURL:        get("RH_IDP_LOGOUT_URL"),
		ProjectURL:          get("RH_PROJECT_URL"),
		ControlURL:          get("RH_CONTROL_URL"),
		ControlToken:        get("RH_CONTROL_TOKEN"),
		ControlTokenFile:    get("RH_CONTROL_TOKEN_FILE"),
		BootstrapAdmin:      strings.ToLower(get("RH_BOOTSTRAP_ADMIN")),
		SecretKey:           get("RH_SECRET_KEY"),
		SecretKeyFile:       get("RH_SECRET_KEY_FILE"),
		GuacPublicPath:      strings.TrimRight(get("RH_GUAC_PUBLIC_PATH"), "/"),
		GuacJSONSecret:      get("RH_GUAC_JSON_SECRET"),
		GuacJSONSecretFile:  get("RH_GUAC_JSON_SECRET_FILE"),
		GuacdAddr:           get("RH_GUACD_ADDR"),
		LogLevel:            strings.ToUpper(get("RH_LOG_LEVEL")),
		Version:             get("RH_VERSION"),
	}
	c.SSHPublicPort = atoi("RH_SSH_PUBLIC_PORT", 1, 65535)
	c.TunnelPortMin = atoi("RH_TUNNEL_PORT_MIN", 1024, 65535)
	c.TunnelPortMax = atoi("RH_TUNNEL_PORT_MAX", 1024, 65535)
	if c.TunnelPortMax < c.TunnelPortMin {
		bad("RH_TUNNEL_PORT_MAX", "must be >= RH_TUNNEL_PORT_MIN")
	}
	switch get("RH_DEBUG_PPROF") {
	case "true", "1":
		c.DebugPprof = true
	case "false", "0", "":
	default:
		bad("RH_DEBUG_PPROF", "must be true or false")
	}

	if c.Env != "production" && c.Env != "development" {
		bad("RH_ENV", "must be production or development")
	}
	for _, a := range []struct{ name, v string }{{"RH_HTTP_ADDR", c.HTTPAddr}, {"RH_METRICS_ADDR", c.MetricsAddr}, {"RH_SSH_ADDR", c.SSHAddr}} {
		if _, _, err := net.SplitHostPort(a.v); err != nil {
			bad(a.name, "must be host:port or :port")
		}
	}
	if ip := net.ParseIP(c.TunnelBind); ip == nil {
		bad("RH_TUNNEL_BIND", "must be an IP address")
	} else if ip.IsUnspecified() && get("RH_TUNNEL_BIND_ALLOW_ANY") != "true" {
		bad("RH_TUNNEL_BIND", "0.0.0.0/:: would expose every device's desktop to the network; bind the guac-network address, or set RH_TUNNEL_BIND_ALLOW_ANY=true")
	}
	if c.TunnelAdvertiseHost == "" {
		bad("RH_TUNNEL_ADVERTISE_HOST", "required")
	}
	if c.DataDir == "" {
		bad("RH_DATA_DIR", "required")
	}
	if u, err := parseHTTPURL(get("RH_PUBLIC_URL"), c.Development()); err != nil {
		bad("RH_PUBLIC_URL", err.Error())
	} else if !validate.PublicURL(get("RH_PUBLIC_URL"), c.Development()) {
		// It seeds settings.public_url, which is substituted into the bootstrap scripts.
		bad("RH_PUBLIC_URL", "use only letters, digits and . - / _ ~ (e.g. https://rh.example.com); no quotes, spaces, query or non-ASCII")
	} else {
		c.PublicURL = u
	}
	if u, err := parseHTTPURL(get("RH_GUAC_URL"), true); err != nil {
		bad("RH_GUAC_URL", err.Error())
	} else {
		c.GuacURL = u
		if strings.TrimRight(u.Path, "/") != c.GuacPublicPath {
			bad("RH_GUAC_PUBLIC_PATH", "must equal the path of RH_GUAC_URL ("+u.Path+") — the proxy does not rewrite paths")
		}
	}
	// Sign-out targets are navigated to by the browser: https only (or a
	// same-origin absolute path for the proxy logout), never javascript: etc.
	if v := c.ProxyLogoutURL; v != "" && !(strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//")) {
		if _, err := parseHTTPURL(v, c.Development()); err != nil {
			bad("RH_PROXY_LOGOUT_URL", err.Error()+" (or a path such as /oauth2/sign_out)")
		}
	}
	if v := c.IdPLogoutURL; v != "" {
		if _, err := parseHTTPURL(v, false); err != nil {
			bad("RH_IDP_LOGOUT_URL", err.Error())
		}
	}
	if v := c.ProjectURL; v != "" {
		if _, err := parseHTTPURL(v, false); err != nil {
			bad("RH_PROJECT_URL", err.Error())
		}
	}
	if c.ControlURL != "" {
		if u, err := parseHTTPURL(c.ControlURL, true); err != nil {
			bad("RH_CONTROL_URL", err.Error())
		} else if u.Path != "" && u.Path != "/" {
			bad("RH_CONTROL_URL", "must be a base URL with no path, e.g. http://rh-control:9091")
		}
	}
	if !strings.HasPrefix(c.GuacPublicPath, "/") || c.GuacPublicPath == "/" {
		bad("RH_GUAC_PUBLIC_PATH", "must be a sub-path such as /guacamole")
	}
	switch c.LogLevel {
	case "DEBUG", "INFO", "WARN", "ERROR":
	default:
		bad("RH_LOG_LEVEL", "must be DEBUG, INFO, WARN or ERROR")
	}

	switch c.AuthMode {
	case "oauth":
		ids := splitList(strings.ToLower(get("RH_AUTH_PROVIDERS")))
		if len(ids) == 0 {
			bad("RH_AUTH_PROVIDERS", "list at least one of: "+strings.Join(ProviderIDs, ", "))
		}
		seen := map[string]bool{}
		for _, id := range ids {
			if !contains(ProviderIDs, id) {
				bad("RH_AUTH_PROVIDERS", fmt.Sprintf("%q is not supported (use %s)", id, strings.Join(ProviderIDs, ", ")))
				continue
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			k := func(f string) string { return "RH_AUTH_" + strings.ToUpper(id) + "_" + f }
			pc := ProviderConfig{ID: id, ClientID: get(k("CLIENT_ID")), ClientSecret: get(k("CLIENT_SECRET")),
				ClientSecretFile: get(k("CLIENT_SECRET_FILE")), Scopes: strings.Fields(get(k("SCOPES"))),
				Tenant: get(k("TENANT")), AllowedTenants: splitList(strings.ToLower(get(k("ALLOWED_TENANTS")))), TrustEmail: get(k("TRUST_EMAIL")) == "true", Issuer: get(k("ISSUER")),
				DisplayName: get(k("NAME")), TeamID: get(k("TEAM_ID")), KeyID: get(k("KEY_ID")), PrivateKeyFile: get(k("PRIVATE_KEY_FILE"))}
			if pc.ClientID == "" {
				bad(k("CLIENT_ID"), "required for provider "+id)
			}
			switch id {
			case "apple":
				if pc.TeamID == "" || pc.KeyID == "" || pc.PrivateKeyFile == "" {
					bad(k("PRIVATE_KEY_FILE"), "apple needs TEAM_ID, KEY_ID and PRIVATE_KEY_FILE")
				}
			default:
				if pc.ClientSecret == "" && pc.ClientSecretFile == "" {
					bad(k("CLIENT_SECRET"), "set it or "+k("CLIENT_SECRET_FILE"))
				}
			}
			if id == "entra" {
				switch strings.ToLower(pc.Tenant) {
				case "":
					bad(k("TENANT"), "required: your tenant ID (or organizations/common together with "+k("ALLOWED_TENANTS")+")")
				case "consumers":
					bad(k("TENANT"), "consumers (personal Microsoft accounts) is not supported; use the google/apple/oidc providers for public sign-in")
				case "organizations", "common":
					if len(pc.AllowedTenants) == 0 {
						bad(k("ALLOWED_TENANTS"), "required for multi-tenant: otherwise an admin of ANY Microsoft tenant could sign in")
					}
				}
			}
			if id == "oidc" {
				if _, err := parseHTTPURL(pc.Issuer, false); err != nil {
					bad(k("ISSUER"), err.Error())
				}
			}
			c.Providers = append(c.Providers, pc)
		}
	case "proxy":
		if get("RH_TRUSTED_PROXIES") == "" {
			bad("RH_TRUSTED_PROXIES", "required when RH_AUTH_MODE=proxy (identity headers are only trusted from these networks)")
		}
		if c.ProxySecret == "" {
			bad("RH_PROXY_SECRET", "required when RH_AUTH_MODE=proxy: configure the proxy to send it in X-RemoteHound-Proxy-Secret (generate with: remotehound gen-secret); a trusted network alone admits anything else on it")
		}
	case "dev":
		if !c.Development() {
			bad("RH_AUTH_MODE", "dev is only allowed with RH_ENV=development")
		}
		if host, _, _ := net.SplitHostPort(c.HTTPAddr); !isLoopback(host) {
			bad("RH_AUTH_MODE", "dev requires RH_HTTP_ADDR on a loopback address, e.g. 127.0.0.1:8080")
		}
	default:
		bad("RH_AUTH_MODE", "must be oidc, proxy or dev")
	}

	for _, raw := range splitList(get("RH_TRUSTED_PROXIES")) {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			bad("RH_TRUSTED_PROXIES", fmt.Sprintf("%q is not a CIDR", raw))
			continue
		}
		c.TrustedProxies = append(c.TrustedProxies, p)
	}

	if c.SecretKey == "" && c.SecretKeyFile == "" && !c.Development() {
		bad("RH_SECRET_KEY", "set it or RH_SECRET_KEY_FILE (generate with: remotehound gen-secret)")
	}
	if c.GuacJSONSecret == "" && c.GuacJSONSecretFile == "" && !c.Development() {
		bad("RH_GUAC_JSON_SECRET", "set it or RH_GUAC_JSON_SECRET_FILE (must equal guacamole's JSON_SECRET_KEY)")
	}

	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, errors.New("invalid configuration:\n  " + strings.Join(errs, "\n  "))
	}
	return c, nil
}

// ControlConfig is the rh-control helper's configuration (`remotehound control`).
// It deliberately reads only its own keys: the helper holds the Docker socket
// and must not need — or be able to read — RemoteHound's master key.
type ControlConfig struct {
	Env          string
	Listen       string
	DockerSocket string
	Token        string
	TokenFile    string
	LogLevel     string
}

// LoadControl reads and validates the helper's environment.
func LoadControl(lookup func(string) (string, bool)) (*ControlConfig, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	get := func(name string) string {
		if v, ok := lookup(name); ok {
			return strings.TrimSpace(v)
		}
		for _, k := range Keys {
			if k.Name == name {
				return k.Default
			}
		}
		return ""
	}
	c := &ControlConfig{Env: get("RH_ENV"), Listen: get("RH_CONTROL_LISTEN"), DockerSocket: get("RH_CONTROL_DOCKER_SOCKET"),
		Token: get("RH_CONTROL_TOKEN"), TokenFile: get("RH_CONTROL_TOKEN_FILE"), LogLevel: strings.ToUpper(get("RH_LOG_LEVEL"))}
	var errs []string
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		errs = append(errs, "RH_CONTROL_LISTEN: must be host:port or :port")
	}
	if !strings.HasPrefix(c.DockerSocket, "/") {
		errs = append(errs, "RH_CONTROL_DOCKER_SOCKET: must be an absolute path")
	}
	if c.Token == "" && c.TokenFile == "" {
		errs = append(errs, "RH_CONTROL_TOKEN: required (or RH_CONTROL_TOKEN_FILE) — the helper refuses to run unauthenticated")
	}
	switch c.LogLevel {
	case "DEBUG", "INFO", "WARN", "ERROR":
	default:
		errs = append(errs, "RH_LOG_LEVEL: must be DEBUG, INFO, WARN or ERROR")
	}
	if len(errs) > 0 {
		return nil, errors.New("invalid configuration:\n  " + strings.Join(errs, "\n  "))
	}
	return c, nil
}

func parseHTTPURL(raw string, allowHTTP bool) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, errors.New("must be an absolute URL")
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return nil, errors.New("must use https")
	}
	return u, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Markdown renders Keys as a documentation table (secrets show no default).
func Markdown() string {
	var b strings.Builder
	b.WriteString("| Variable | Default | Required | Description |\n|---|---|---|---|\n")
	for _, k := range Keys {
		def := k.Default
		if k.Secret {
			def = "*(secret)*"
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s |\n", k.Name, def, k.Required, k.Help)
	}
	return b.String()
}
