package auth

// @feature:users — sign-in providers, identity resolution and account-takeover guards.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jchirayath/remotehound/internal/core/config"
	"github.com/jchirayath/remotehound/internal/core/httpx"
	"github.com/jchirayath/remotehound/internal/core/store"
	"github.com/jchirayath/remotehound/internal/model"
)

// fakeIdP is a TLS OIDC issuer that signs ID tokens with an RSA key.
type fakeIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	claims func(nonce string) map[string]any
	alg    string
	nonce  string
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newIdP(t *testing.T) *fakeIdP {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeIdP{key: k, alg: "RS256"}
	mux := http.NewServeMux()
	f.srv = httptest.NewTLSServer(mux)
	iss := f.srv.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": iss, "authorization_endpoint": iss + "/authorize",
			"token_endpoint": iss + "/token", "jwks_uri": iss + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig",
			"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.PostForm.Get("code_verifier") == "" || r.PostForm.Get("code") != "good-code" {
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": f.sign(f.claims(f.nonce))})
	})
	t.Cleanup(f.srv.Close)
	f.claims = func(nonce string) map[string]any {
		return map[string]any{"iss": iss, "aud": "client-1", "sub": "user-123", "email": "ada@example.com", "email_verified": true,
			"name": "Ada", "nonce": nonce, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "groups": []string{"rh-admins"}}
	}
	return f
}

func (f *fakeIdP) sign(cl map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": f.alg, "kid": "k1", "typ": "JWT"})
	p, _ := json.Marshal(cl)
	in := b64(h) + "." + b64(p)
	d := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, f.key, 5 /* crypto.SHA256 */, d[:])
	return in + "." + b64(sig)
}

func (f *fakeIdP) provider() *OIDC {
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	return &OIDC{ProviderID: "oidc", Name: "Test", Kind: "oidc", Issuer: f.srv.URL, ClientID: "client-1", ClientSecret: "s",
		RedirectURL: "https://rh.example.com/auth/callback/oidc", Scopes: []string{"openid", "email"},
		HTTP: httpx.New(httpx.Options{AllowPrivate: []string{"127.0.0.1"}, RootCAs: pool})}
}

// run performs Start + Finish like a browser would and returns the identity.
func run(t *testing.T, f *fakeIdP, p *OIDC, tamper func(q url.Values)) (Identity, error) {
	t.Helper()
	sess := &Sessions{Key: []byte(strings.Repeat("k", 32)), Secure: true}
	w := httptest.NewRecorder()
	authURL, err := p.Start(context.Background(), w, sess, NewFlow("/devices", "", "groups"))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("nonce") == "" {
		t.Fatalf("authorize URL lacks PKCE/state/nonce: %s", authURL)
	}
	f.nonce = q.Get("nonce")
	cb := url.Values{"state": {q.Get("state")}, "code": {"good-code"}}
	if tamper != nil {
		tamper(cb)
	}
	r := httptest.NewRequest("GET", "/auth/callback/oidc?"+cb.Encode(), nil)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	fl, err := sess.TakeFlow(httptest.NewRecorder(), r)
	if err != nil {
		t.Fatal(err)
	}
	return p.Finish(context.Background(), httptest.NewRecorder(), r, sess, fl)
}

func TestOIDCHappyPath(t *testing.T) {
	f := newIdP(t)
	id, err := run(t, f, f.provider(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if id.Provider != "oidc" || id.Subject != "user-123" || !id.EmailVerified || id.Groups[0] != "rh-admins" {
		t.Fatalf("%+v", id)
	}
}

func TestOIDCRejections(t *testing.T) {
	cases := map[string]func(f *fakeIdP, p *OIDC) func(url.Values){
		"state mismatch": func(f *fakeIdP, p *OIDC) func(url.Values) { return func(q url.Values) { q.Set("state", "evil") } },
		"wrong audience": func(f *fakeIdP, p *OIDC) func(url.Values) {
			old := f.claims
			f.claims = func(n string) map[string]any { c := old(n); c["aud"] = "someone-else"; return c }
			return nil
		},
		"wrong issuer": func(f *fakeIdP, p *OIDC) func(url.Values) {
			old := f.claims
			f.claims = func(n string) map[string]any { c := old(n); c["iss"] = "https://evil.example"; return c }
			return nil
		},
		"expired": func(f *fakeIdP, p *OIDC) func(url.Values) {
			old := f.claims
			f.claims = func(n string) map[string]any { c := old(n); c["exp"] = time.Now().Add(-time.Hour).Unix(); return c }
			return nil
		},
		"nonce replay": func(f *fakeIdP, p *OIDC) func(url.Values) {
			old := f.claims
			f.claims = func(string) map[string]any { return old("stale-nonce") }
			return nil
		},
		"alg none":  func(f *fakeIdP, p *OIDC) func(url.Values) { f.alg = "none"; return nil },
		"alg HS256": func(f *fakeIdP, p *OIDC) func(url.Values) { f.alg = "HS256"; return nil },
		"bad code":  func(f *fakeIdP, p *OIDC) func(url.Values) { return func(q url.Values) { q.Set("code", "nope") } },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newIdP(t)
			p := f.provider()
			if _, err := run(t, f, p, setup(f, p)); err == nil {
				t.Fatalf("%s accepted", name)
			}
		})
	}
}

func TestTamperedSignatureRejected(t *testing.T) {
	f := newIdP(t)
	p := f.provider()
	tok := f.sign(f.claims("n"))
	parts := strings.Split(tok, ".")
	pl, _ := json.Marshal(map[string]any{"iss": f.srv.URL, "aud": "client-1", "sub": "attacker", "nonce": "n", "exp": time.Now().Add(time.Hour).Unix()})
	if _, err := p.Verify(context.Background(), parts[0]+"."+b64(pl)+"."+parts[2], "n"); err == nil {
		t.Fatal("tampered payload accepted")
	}
}

func TestAppleSecretIsVerifiableES256(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	fn, err := AppleSecret("TEAM123", "KEY456", "com.example.rh", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	jwt, _ := fn()
	parts := strings.Split(jwt, ".")
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !ecdsa.Verify(&k.PublicKey, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("apple client secret signature invalid")
	}
	var cl map[string]any
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(pb, &cl)
	if cl["iss"] != "TEAM123" || cl["sub"] != "com.example.rh" || cl["aud"] != "https://appleid.apple.com" {
		t.Fatalf("claims %v", cl)
	}
}

func TestIdentityFromAppleStringEmailVerified(t *testing.T) {
	id := identityFrom(map[string]any{"sub": "a", "email": "X@Privaterelay.appleid.com", "email_verified": "true"}, "")
	if !id.EmailVerified || id.Email != "x@privaterelay.appleid.com" {
		t.Fatalf("%+v", id)
	}
}

// ---- Resolve: who gets in, and the takeover guards ----------------------------

func newAuth(t *testing.T) *Authenticator {
	st, err := store.Open(t.TempDir(), func(s *model.State) { s.Settings = model.DefaultSettings("https://rh", "rh", 2222) })
	if err != nil {
		t.Fatal(err)
	}
	return &Authenticator{Store: st, BootstrapAdmin: "boss@example.com"}
}

func TestBootstrapAdminNeedsVerifiedEmail(t *testing.T) {
	a := newAuth(t)
	if _, err := a.Resolve(context.Background(), Identity{Provider: "github", Subject: "1", Email: "boss@example.com", EmailVerified: false}, "", true); err == nil {
		t.Fatal("unverified email became bootstrap admin")
	}
	u, err := a.Resolve(context.Background(), Identity{Provider: "google", Subject: "g1", Email: "boss@example.com", EmailVerified: true}, "", true)
	if err != nil || u.Role != model.RoleAdmin {
		t.Fatalf("bootstrap: %v %+v", err, u)
	}
	// A second verified identity with the same email does NOT silently attach.
	if _, err := a.Resolve(context.Background(), Identity{Provider: "facebook", Subject: "f1", Email: "boss@example.com", EmailVerified: true}, "", true); err == nil {
		t.Fatal("another provider identity attached by email alone")
	}
}

func TestPreAuthorizedEmailBindsOnlyWhenVerified(t *testing.T) {
	a := newAuth(t)
	_ = a.Store.Update(func(s *model.State) error {
		s.Users["usr_pre"] = &model.User{Meta: model.Meta{ID: "usr_pre", Version: 1}, Email: "op@example.com", Role: model.RoleOperator}
		s.Users["usr_admin"] = &model.User{Meta: model.Meta{ID: "usr_admin", Version: 1}, Email: "x@x", Role: model.RoleAdmin,
			Identities: []model.UserIdentity{{Provider: "google", Subject: "adm"}}}
		return nil
	})
	if _, err := a.Resolve(context.Background(), Identity{Provider: "oidc", Subject: "o1", Email: "op@example.com"}, "", true); err == nil {
		t.Fatal("unverified email bound to a pre-authorized user")
	}
	u, err := a.Resolve(context.Background(), Identity{Provider: "entra", Subject: "e1", Email: "op@example.com", EmailVerified: true}, "", true)
	if err != nil || u.ID != "usr_pre" || len(u.Identities) != 1 {
		t.Fatalf("%v %+v", err, u)
	}
	// Same person signs in again: matched by provider identity, not email.
	u2, err := a.Resolve(context.Background(), Identity{Provider: "entra", Subject: "e1", Email: "changed@example.com"}, "", true)
	if err != nil || u2.ID != "usr_pre" {
		t.Fatalf("returning sign-in: %v %+v", err, u2)
	}
}

func TestLinkingRules(t *testing.T) {
	a := newAuth(t)
	_ = a.Store.Update(func(s *model.State) error {
		s.Users["usr_a"] = &model.User{Meta: model.Meta{ID: "usr_a", Version: 1}, Email: "a@x", Role: model.RoleOperator,
			Identities: []model.UserIdentity{{Provider: "google", Subject: "ga"}}}
		s.Users["usr_b"] = &model.User{Meta: model.Meta{ID: "usr_b", Version: 1}, Email: "b@x", Role: model.RoleOperator,
			Identities: []model.UserIdentity{{Provider: "github", Subject: "hb"}}}
		return nil
	})
	u, err := a.Resolve(context.Background(), Identity{Provider: "entra", Subject: "ea"}, "usr_a", true)
	if err != nil || len(u.Identities) != 2 {
		t.Fatalf("link: %v %+v", err, u)
	}
	if _, err := a.Resolve(context.Background(), Identity{Provider: "github", Subject: "hb"}, "usr_a", true); err == nil {
		t.Fatal("linked an identity that belongs to another user")
	}
}

func TestRolesMapJITAndDenyByDefault(t *testing.T) {
	a := newAuth(t)
	_ = a.Store.Update(func(s *model.State) error {
		s.Settings.RolesMap = map[string]string{"rh-ops": model.RoleOperator}
		return nil
	})
	if _, err := a.Resolve(context.Background(), Identity{Provider: "entra", Subject: "x", Email: "x@x"}, "", true); err == nil {
		t.Fatal("unknown user admitted")
	}
	u, err := a.Resolve(context.Background(), Identity{Provider: "entra", Subject: "y", Groups: []string{"rh-ops"}}, "", true)
	if err != nil || u.Role != model.RoleOperator {
		t.Fatalf("%v %+v", err, u)
	}
}

func TestSafeReturn(t *testing.T) {
	for in, want := range map[string]string{"/devices": "/devices", "https://evil": "/", "//evil": "/", "/\\evil": "/", "": "/"} {
		if got := SafeReturn(in); got != want {
			t.Errorf("%q → %q", in, got)
		}
	}
}

// Regression (security review P0): multi-tenant Entra must only accept
// explicitly allowed tenants — an admin of any other tenant was able to sign in.
func TestEntraMultiTenantRejectsForeignTenants(t *testing.T) {
	p, err := Build(config.ProviderConfig{ID: "entra", ClientID: "c", Tenant: "organizations", AllowedTenants: []string{"aaaaaaaa-home"}}, Credentials{ClientSecret: "s"}, "https://rh")
	if err != nil {
		t.Fatal(err)
	}
	o := p.(*OIDC)
	if o.AcceptIssuers("https://login.microsoftonline.com/11111111-attacker/v2.0") {
		t.Fatal("foreign tenant issuer accepted")
	}
	if !o.AcceptIssuers("https://login.microsoftonline.com/aaaaaaaa-home/v2.0") {
		t.Fatal("allowed tenant rejected")
	}
	single, _ := Build(config.ProviderConfig{ID: "entra", ClientID: "c", Tenant: "bbbbbbbb-own"}, Credentials{ClientSecret: "s"}, "https://rh")
	if single.(*OIDC).AcceptIssuers != nil || single.(*OIDC).Issuer != "https://login.microsoftonline.com/bbbbbbbb-own/v2.0" {
		t.Fatal("single tenant must pin the exact issuer")
	}
}

// Regression (security review P2): tab/backslash tricks must not open-redirect.
func TestSafeReturnRejectsWhitespaceTricks(t *testing.T) {
	for _, rd := range []string{"/\t/evil.example", "/\t\\evil", "/\\evil", "/%09/evil", "/ok\x7f"} {
		got := SafeReturn(rd)
		if got != "/" && rd != "/%09/evil" {
			t.Errorf("%q → %q", rd, got)
		}
	}
	if SafeReturn("/devices?x=1") != "/devices?x=1" {
		t.Fatal("normal path rejected")
	}
}

// Regression: a session cookie must not be accepted as a flow cookie and vice versa.
func TestCookiePurposesAreSeparated(t *testing.T) {
	s := &Sessions{Key: []byte(strings.Repeat("k", 32)), Secure: true}
	w := httptest.NewRecorder()
	s.Issue(w, "usr_1", 0)
	r := httptest.NewRequest("GET", "/auth/callback/google", nil)
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookie {
			r.AddCookie(&http.Cookie{Name: "rh_oidc", Value: c.Value})
		}
	}
	if _, err := s.TakeFlow(httptest.NewRecorder(), r); err == nil {
		t.Fatal("session cookie accepted as a login flow")
	}
}

// Regression (automated review): preferred_username is never a verified
// email, even on a TrustEmail issuer.
func TestPreferredUsernameIsNeverVerified(t *testing.T) {
	f := newIdP(t)
	old := f.claims
	f.claims = func(n string) map[string]any {
		c := old(n)
		delete(c, "email")
		delete(c, "email_verified")
		c["preferred_username"] = "boss@example.com"
		return c
	}
	p := f.provider()
	p.TrustEmail = true
	id, err := run(t, f, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if id.EmailVerified {
		t.Fatal("preferred_username treated as a verified email")
	}
}

func TestPersonNameDropsIDsAndEmails(t *testing.T) {
	for in, want := range map[string]string{
		"Ada Lovelace": "Ada Lovelace",
		"adal":         "adal",
		"  Ana  ":      "Ana",
		"7HFBnaKsHAmdpqMfN6_ip0w2wqFvN0ccPfJPYXhxXYc": "",
		"3f2b9c1e-8d4a-4f6b-9e2a-1c7d5b8a9f00":        "",
		"adal@example.com":                            "",
		"":                                            "",
	} {
		if got := personName(in); got != want {
			t.Errorf("personName(%q) = %q, want %q", in, got, want)
		}
	}
}
