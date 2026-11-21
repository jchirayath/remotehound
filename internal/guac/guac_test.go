package guac

// @feature:integration

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

var key, _ = hex.DecodeString("4c0b569e4c96df157eee1b65dd0e4d41")

func TestSealOpenRoundTrip(t *testing.T) {
	in := AuthData{Username: "ada@example.com", Expires: Expiry(time.Unix(1700000000, 0), time.Minute),
		Connections: map[string]Connection{"laptop · RDP": {Protocol: "rdp", Parameters: map[string]string{"hostname": "remotehound", "port": "20001"}}}}
	sealed, err := Seal(key, in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Open(key, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if out.Username != in.Username || out.Connections["laptop · RDP"].Parameters["port"] != "20001" {
		t.Fatalf("round trip mismatch: %+v", out)
	}
}

// TestSealMatchesReferenceAlgorithm decrypts independently, exactly as
// guacamole-auth-json documents it (AES-128-CBC, zero IV, HMAC-SHA256 prefix).
func TestSealMatchesReferenceAlgorithm(t *testing.T) {
	sealed, _ := Seal(key, AuthData{Username: "u", Expires: 1, Connections: map[string]Connection{}})
	raw, _ := base64.StdEncoding.DecodeString(sealed)
	block, _ := aes.NewCipher(key)
	plain := make([]byte, len(raw))
	cipher.NewCBCDecrypter(block, make([]byte, 16)).CryptBlocks(plain, raw)
	plain = plain[:len(plain)-int(plain[len(plain)-1])]
	mac := hmac.New(sha256.New, key)
	mac.Write(plain[32:])
	if !bytes.Equal(mac.Sum(nil), plain[:32]) {
		t.Fatal("signature prefix is not HMAC-SHA256 of the JSON")
	}
	var d map[string]any
	if err := json.Unmarshal(plain[32:], &d); err != nil || d["username"] != "u" {
		t.Fatalf("payload is not the JSON document: %s", plain[32:])
	}
}

func TestOpenRejectsTamperingAndWrongKey(t *testing.T) {
	sealed, _ := Seal(key, AuthData{Username: "u", Connections: map[string]Connection{}})
	raw, _ := base64.StdEncoding.DecodeString(sealed)
	raw[len(raw)-20] ^= 0xff
	if _, err := Open(key, base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("tampered blob accepted")
	}
	other, _ := hex.DecodeString("00000000000000000000000000000001")
	if _, err := Open(other, sealed); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := Seal([]byte("short"), AuthData{}); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestConnectURLShape(t *testing.T) {
	u := ConnectURL("/guacamole", "laptop · SSH", "a+b/c=")
	if !strings.HasPrefix(u, "/guacamole/?data=a%2Bb%2Fc%3D#/client/") {
		t.Fatalf("bad url %s", u)
	}
	id, _ := url.PathUnescape(strings.SplitN(u, "#/client/", 2)[1])
	dec, _ := base64.StdEncoding.DecodeString(id)
	if string(dec) != "laptop · SSH\x00c\x00json" {
		t.Fatalf("client identifier = %q", dec)
	}
}

func TestGuacdVersionParsing(t *testing.T) {
	if v := guacdVersion("4.args,13.VERSION_1_6_0,8.hostname,4.port;"); v != "1.6.0" {
		t.Fatalf("got %q", v)
	}
	if v := guacdVersion("garbage"); v != "" {
		t.Fatalf("got %q", v)
	}
}

func FuzzOpen(f *testing.F) {
	s, _ := Seal(key, AuthData{Username: "x", Connections: map[string]Connection{}})
	f.Add(s)
	f.Add("")
	f.Add("AAAA")
	f.Fuzz(func(t *testing.T, data string) {
		_, _ = Open(key, data) // must never panic on untrusted input (TEST-10)
	})
}
