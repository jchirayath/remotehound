package device

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/jchirayath/remotehound/internal/core/apierr"
	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/core/authz"
	"github.com/jchirayath/remotehound/internal/core/ids"
	"github.com/jchirayath/remotehound/internal/model"
)

// Personal credentials: each user saves their own login per device service so
// Connect opens THEIR OS session. Sealed with AAD = user/device/service, so a
// credential can never be decrypted into anyone else's connection, and no API
// (admin included) ever returns the secret.

func credentialAAD(userID, deviceID, kind string) string {
	return "cred/" + userID + "/" + deviceID + "/" + kind
}

func (s *Service) userCredential(userID, deviceID, kind string) *model.Credential {
	var out *model.Credential
	s.Store.View(func(st *model.State) {
		if c, ok := st.Credentials[model.CredentialKey(userID, deviceID, kind)]; ok {
			cp := *c
			out = &cp
		}
	})
	return out
}

// CredentialView never includes the secret.
type CredentialView struct {
	DeviceID      string    `json:"device_id"`
	DeviceName    string    `json:"device_name"`
	DeviceDeleted bool      `json:"device_deleted,omitempty"`
	Service       string    `json:"service"`
	Username      string    `json:"username"`
	Auth          string    `json:"auth"` // password | key
	UpdatedAt     time.Time `json:"updated_at"`
}

func authKind(c *model.Credential) string {
	if c.SealedKey != "" {
		return "key"
	}
	return "password"
}

// ValidPrivateKey accepts PEM / OpenSSH private keys only (≤ 16 KiB). Guacamole
// passes it to libssh2, which reads PEM RSA/ECDSA and OpenSSH ed25519 keys.
func ValidPrivateKey(k string) bool {
	k = strings.TrimSpace(k)
	return len(k) <= 16<<10 && strings.HasPrefix(k, "-----BEGIN ") && strings.Contains(k, "PRIVATE KEY-----") &&
		strings.Contains(k, "-----END ")
}

// MyCredentials lists the caller's saved logins.
func (s *Service) MyCredentials(a *authz.Actor) []CredentialView {
	out := []CredentialView{}
	s.Store.View(func(st *model.State) {
		for _, c := range st.Credentials {
			if c.UserID != a.UserID {
				continue
			}
			v := CredentialView{DeviceID: c.DeviceID, Service: c.Service, Username: c.Username, Auth: authKind(c), UpdatedAt: c.UpdatedAt, DeviceName: "(deleted device)", DeviceDeleted: true}
			if d := st.Devices[c.DeviceID]; d != nil {
				v.DeviceName, v.DeviceDeleted = d.Name, false
			}
			out = append(out, v)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceName+out[i].Service < out[j].DeviceName+out[j].Service })
	return out
}

// SaveCredential stores the caller's own login for a device they can connect
// to: a password, or (ssh only) a private key with an optional passphrase.
func (s *Service) SaveCredential(ctx context.Context, a *authz.Actor, deviceID, kind, username, password, privateKey string) (CredentialView, error) {
	if _, ok := model.DefaultRemotePort[kind]; !ok {
		return CredentialView{}, apierr.BadRequest(apierr.CodeValidation, "Service must be ssh, rdp or vnc.")
	}
	privateKey = strings.TrimSpace(privateKey)
	switch {
	case privateKey != "" && kind != model.ServiceSSH:
		return CredentialView{}, apierr.Validation([]apierr.FieldError{{Pointer: "/private_key", Code: "NOT_ALLOWED", Detail: "Keys are for SSH logins only."}})
	case privateKey != "" && !ValidPrivateKey(privateKey):
		return CredentialView{}, apierr.Validation([]apierr.FieldError{{Pointer: "/private_key", Code: "INVALID", Detail: "Paste the whole private key, from -----BEGIN … PRIVATE KEY----- to the END line."}})
	case privateKey == "" && password == "":
		return CredentialView{}, apierr.Validation([]apierr.FieldError{{Pointer: "/password", Code: "REQUIRED", Detail: "Enter the password (or, for SSH, paste a private key)."}})
	}
	d, err := s.Load(a, authz.DeviceConnect, deviceID)
	if err != nil {
		return CredentialView{}, err
	}
	aad := credentialAAD(a.UserID, deviceID, kind)
	sealed, sealedKey := "", ""
	if password != "" {
		if sealed, err = s.Secrets.Seal(password, aad); err != nil {
			return CredentialView{}, apierr.Internal(err)
		}
	}
	if privateKey != "" {
		if sealedKey, err = s.Secrets.Seal(privateKey+"\n", aad+"/key"); err != nil {
			return CredentialView{}, apierr.Internal(err)
		}
	}
	now := time.Now().UTC()
	key := model.CredentialKey(a.UserID, deviceID, kind)
	err = s.Store.Update(func(st *model.State) error {
		c, ok := st.Credentials[key]
		if !ok {
			c = &model.Credential{Meta: model.Meta{ID: ids.New("crd"), CreatedAt: now, Version: 0}, UserID: a.UserID, DeviceID: deviceID, Service: kind}
			st.Credentials[key] = c
		}
		c.Username, c.Sealed, c.SealedKey = strings.TrimSpace(username), sealed, sealedKey
		c.Touch(now)
		return nil
	})
	if err != nil {
		return CredentialView{}, err
	}
	auth := "password"
	if sealedKey != "" {
		auth = "key"
	}
	s.Audit.Record(ctx, "credential.save", audit.Success, "device:"+deviceID, map[string]any{"service": kind, "auth": auth})
	return CredentialView{DeviceID: deviceID, DeviceName: d.Name, Service: kind, Username: strings.TrimSpace(username), Auth: auth, UpdatedAt: now}, nil
}

// DeleteCredential removes the caller's own saved login.
func (s *Service) DeleteCredential(ctx context.Context, a *authz.Actor, deviceID, kind string) error {
	key := model.CredentialKey(a.UserID, deviceID, kind)
	err := s.Store.Update(func(st *model.State) error {
		if _, ok := st.Credentials[key]; !ok {
			return apierr.NotFound(apierr.CodeNotFound, "No saved login for that device and service.")
		}
		delete(st.Credentials, key)
		return nil
	})
	if err == nil {
		s.Audit.Record(ctx, "credential.delete", audit.Success, "device:"+deviceID, map[string]any{"service": kind})
	}
	return err
}
