// Package guac is the Guacamole integration (ADR-0001).
//
// RemoteHound never stores users or connections in Guacamole. For each
// "Connect" it builds one connection definition, seals it in the
// guacamole-auth-json format and hands the browser a URL Guacamole redeems:
//
//	payload   = HMAC-SHA256(key, json) || json
//	encrypted = AES-128-CBC(key, IV = 16 zero bytes, PKCS#7(payload))
//	data      = base64(encrypted)          → POST /api/tokens  data=<data>
//
// The key is the 128-bit JSON_SECRET_KEY shared with the guacamole container.
// A zero IV is what the extension specifies; it is safe here because the
// HMAC prefix makes every plaintext's first block unique.
package guac

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"time"
)

// Connection is one Guacamole connection inside the auth blob.
type Connection struct {
	Protocol   string            `json:"protocol,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
	ID         string            `json:"id,omitempty"`   // set on a connection that may be joined later
	Join       string            `json:"join,omitempty"` // the id of an active connection to join (no protocol then)
}

// AuthData is the guacamole-auth-json document.
type AuthData struct {
	Username    string                `json:"username"`
	Expires     int64                 `json:"expires"` // epoch milliseconds
	Connections map[string]Connection `json:"connections"`
}

// DataSource is the identifier Guacamole gives the JSON auth provider.
const DataSource = "json"

// Seal signs and encrypts d with key (16 bytes).
func Seal(key []byte, d AuthData) (string, error) {
	if len(key) != 16 {
		return "", errors.New("guacamole JSON key must be 16 bytes")
	}
	plain, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(plain)
	payload := append(mac.Sum(nil), plain...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad(payload, aes.BlockSize)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(out, padded) // #nosec G407 -- zero IV mandated by guacamole-auth-json; HMAC prefix makes blocks unique
	return base64.StdEncoding.EncodeToString(out), nil
}

// Open reverses Seal and verifies the signature (used by tests and by the
// integration self-check to prove both sides agree on the format).
func Open(key []byte, data string) (AuthData, error) {
	var d AuthData
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil || len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
		return d, errors.New("malformed data")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return d, err
	}
	plain := make([]byte, len(raw))
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(plain, raw)
	plain, err = pkcs7Unpad(plain, aes.BlockSize)
	if err != nil || len(plain) < sha256.Size {
		return d, errors.New("malformed data")
	}
	sig, body := plain[:sha256.Size], plain[sha256.Size:]
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	if subtle.ConstantTimeCompare(sig, mac.Sum(nil)) != 1 {
		return d, errors.New("signature mismatch")
	}
	return d, json.Unmarshal(body, &d)
}

func pkcs7Pad(b []byte, n int) []byte {
	p := n - len(b)%n
	return append(b, bytes.Repeat([]byte{byte(p)}, p)...)
}

func pkcs7Unpad(b []byte, n int) ([]byte, error) {
	if len(b) == 0 || len(b)%n != 0 {
		return nil, errors.New("bad padding")
	}
	p := int(b[len(b)-1])
	if p == 0 || p > n || p > len(b) {
		return nil, errors.New("bad padding")
	}
	for _, c := range b[len(b)-p:] {
		if int(c) != p {
			return nil, errors.New("bad padding")
		}
	}
	return b[:len(b)-p], nil
}

// ClientIdentifier is Guacamole's client route id: base64(id NUL "c" NUL dataSource).
func ClientIdentifier(connectionID string) string {
	return base64.StdEncoding.EncodeToString([]byte(connectionID + "\x00c\x00" + DataSource))
}

// ConnectURL is the browser URL that redeems data and opens the connection.
// publicPath is e.g. "/guacamole". The data parameter is short-lived (the
// blob's expires) and is scrubbed from every RemoteHound log line.
func ConnectURL(publicPath, connectionID, sealed string) string {
	return publicPath + "/?data=" + url.QueryEscape(sealed) + "#/client/" + url.PathEscape(ClientIdentifier(connectionID))
}

// Expiry returns the epoch-ms expiry for a TTL from now.
func Expiry(now time.Time, ttl time.Duration) int64 { return now.Add(ttl).UnixMilli() }
