package api

import (
	"net/http"
	"strings"

	"github.com/jchirayath/remotehound/internal/core/apierr"
	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/core/authz"
	"github.com/jchirayath/remotehound/internal/core/validate"
	"github.com/jchirayath/remotehound/internal/device"
	"github.com/jchirayath/remotehound/internal/model"
)

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.DeviceRead) {
		return
	}
	q := r.URL.Query()
	var v validate.Collector
	v.MaxLen("/q", q.Get("q"), 100)
	v.OneOf("/status", q.Get("status"), model.DeviceActive, model.DeviceDisabled, "pending")
	v.OneOf("/os", q.Get("os"), "linux", "macos", "windows", "unknown")
	v.OneOf("/order_by", q.Get("order_by"), "name", "name desc", "last_seen_at", "last_seen_at desc", "created_at", "created_at desc")
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	size, token := pageParams(r)
	status := q.Get("status")
	if status == "pending" {
		status = "" // pending = never seen; filtered below
	}
	items, next, total := s.Devices.List(authz.ActorFrom(r.Context()), device.Filter{
		Q: q.Get("q"), Status: status, GroupID: q.Get("group_id"), OS: q.Get("os"), OrderBy: q.Get("order_by"),
		Online: boolParam(r, "online"), PageSize: size, PageToken: token,
	})
	if q.Get("status") == "pending" {
		kept := items[:0]
		for _, d := range items {
			if d.LastSeenAt == nil {
				kept = append(kept, d)
			}
		}
		items = kept
	}
	if items == nil {
		items = []device.View{}
	}
	writeJSON(w, http.StatusOK, items, &meta{NextPageToken: next, Total: total})
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request) {
	d, err := s.Devices.Load(authz.ActorFrom(r.Context()), authz.DeviceRead, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v := s.Devices.ToView(d)
	w.Header().Set("ETag", v.ETag)
	writeJSON(w, http.StatusOK, v, nil)
}

func (s *Server) createDevice(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.DeviceCreate) {
		return
	}
	var in struct {
		Name      string `json:"name"`
		GroupID   string `json:"group_id"`
		PublicKey string `json:"public_key"`
		OS        string `json:"os"`
		Notes     string `json:"notes"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	var v validate.Collector
	v.Name("/name", in.Name)
	v.ID("/group_id", in.GroupID, "grp")
	v.Required("/public_key", in.PublicKey)
	v.OneOf("/os", in.OS, "linux", "macos", "windows", "unknown")
	v.MaxLen("/notes", in.Notes, 2000)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	d, err := s.Devices.Create(r.Context(), in.Name, in.GroupID, in.PublicKey, in.OS, in.Notes, "")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.Services = []model.Service{{Kind: model.ServiceSSH, RemotePort: 22}}
	err = s.Store.Update(func(st *model.State) error {
		if in.GroupID != "" {
			if _, ok := st.Groups[in.GroupID]; !ok {
				return apierr.BadRequest(apierr.CodeGroupNotFound, "That group does not exist.")
			}
		}
		for _, o := range st.Devices {
			if o.KeyFingerprint == d.KeyFingerprint {
				return apierr.Conflict(apierr.CodeEnrollKeyInvalid, "This key already belongs to another device.")
			}
		}
		st.Devices[d.ID] = d
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Audit.Record(r.Context(), "device.create", audit.Success, "device:"+d.ID, nil)
	writeJSON(w, http.StatusCreated, s.Devices.ToView(d), nil)
}

func (s *Server) patchDevice(w http.ResponseWriter, r *http.Request) {
	etag, err := ifMatch(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var p device.Patch
	if err := decode(r, &p); err != nil {
		s.fail(w, r, err)
		return
	}
	var v validate.Collector
	if p.Name != nil {
		v.Name("/name", *p.Name)
	}
	if p.GroupID != nil {
		v.ID("/group_id", *p.GroupID, "grp")
	}
	if p.Notes != nil {
		v.MaxLen("/notes", *p.Notes, 2000)
	}
	if p.Tags != nil {
		v.Tags("/tags", *p.Tags)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Devices.Update(r.Context(), authz.ActorFrom(r.Context()), r.PathValue("id"), etag, p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", out.ETag)
	writeJSON(w, http.StatusOK, out, nil)
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.Devices.Delete(r.Context(), authz.ActorFrom(r.Context()), r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) putService(w http.ResponseWriter, r *http.Request) {
	var in device.ServiceInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	var v validate.Collector
	v.MaxLen("/username", in.Username, 128)
	if in.Password != nil {
		v.MaxLen("/password", *in.Password, 512)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Devices.UpsertService(r.Context(), authz.ActorFrom(r.Context()), r.PathValue("id"), r.PathValue("kind"), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out, nil)
}

func (s *Server) deleteService(w http.ResponseWriter, r *http.Request) {
	out, err := s.Devices.DeleteService(r.Context(), authz.ActorFrom(r.Context()), r.PathValue("id"), r.PathValue("kind"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out, nil)
}

func (s *Server) connectDevice(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Service string `json:"service"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	var v validate.Collector
	v.Required("/service", in.Service)
	v.OneOf("/service", in.Service, model.ServiceSSH, model.ServiceRDP, model.ServiceVNC)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.Devices.Connect(r.Context(), authz.ActorFrom(r.Context()), r.PathValue("id"), in.Service)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res, nil)
}

func (s *Server) reconnectDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.Devices.Reconnect(r.Context(), authz.ActorFrom(r.Context()), r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) setStatus(w http.ResponseWriter, r *http.Request, status string) {
	out, err := s.Devices.SetStatus(r.Context(), authz.ActorFrom(r.Context()), r.PathValue("id"), status)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out, nil)
}

func (s *Server) disableDevice(w http.ResponseWriter, r *http.Request) {
	s.setStatus(w, r, model.DeviceDisabled)
}
func (s *Server) enableDevice(w http.ResponseWriter, r *http.Request) {
	s.setStatus(w, r, model.DeviceActive)
}

func (s *Server) probeDevice(w http.ResponseWriter, r *http.Request) {
	res, err := s.Devices.Probe(r.Context(), authz.ActorFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res, nil)
}

func (s *Server) deviceLogs(w http.ResponseWriter, r *http.Request) {
	a := authz.ActorFrom(r.Context())
	id := r.PathValue("id")
	// Group-scoped: operators read client logs of devices in their groups only.
	// The cross-device Logs screen (/api/v1/logs) is admin-only (logs.read).
	if _, err := s.Devices.Load(a, authz.DeviceUpdate, id); err != nil {
		s.fail(w, r, err)
		return
	}
	lines := s.Devices.ClientLogs(id)
	if lines == nil {
		lines = []device.LogLine{}
	}
	writeJSON(w, http.StatusOK, lines, nil)
}

// lower-cases and trims a free-text query param.
func qparam(r *http.Request, k string) string { return strings.TrimSpace(r.URL.Query().Get(k)) }
