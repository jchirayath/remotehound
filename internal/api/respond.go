package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/jchirayath/remotehound/internal/core/apierr"
	"github.com/jchirayath/remotehound/internal/core/authz"
	"github.com/jchirayath/remotehound/internal/core/logx"
)

// envelope is the success body shape {data, meta} (CORE-12).
type envelope struct {
	Data any   `json:"data"`
	Meta *meta `json:"meta,omitempty"`
}

type meta struct {
	NextPageToken string `json:"next_page_token"`
	Total         int    `json:"total"`
}

func writeJSON(w http.ResponseWriter, status int, data any, m *meta) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope{Data: data, Meta: m}) // client gone: nothing to do
}

// fail renders err and logs it (5xx at ERROR with the cause; 4xx at INFO/WARN).
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	e := apierr.As(err)
	sc := logx.ScopeFrom(r.Context())
	switch {
	case e.Status >= 500:
		logx.L().ErrorContext(r.Context(), "Request failed", logx.Event("http.error"), logx.Err(e))
	case e.Status == http.StatusForbidden:
		logx.L().WarnContext(r.Context(), "Request denied", logx.Event("http.denied"), slog.String("error.type", e.Code))
	default:
		logx.L().InfoContext(r.Context(), "Request rejected", logx.Event("http.rejected"), slog.String("error.type", e.Code))
	}
	apierr.Write(w, r, sc.RequestID, e)
}

// decode reads a JSON body strictly: size cap, unknown fields rejected
// (mass-assignment and typo guard, SEC-10), single value.
func decode(r *http.Request, v any) error {
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(ct, "application/json") && !strings.HasPrefix(ct, "application/merge-patch+json") {
		return apierr.New(http.StatusUnsupportedMediaType, apierr.CodeBadJSON, "Send JSON (Content-Type: application/json).")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var se *json.SyntaxError
		var te *json.UnmarshalTypeError
		switch {
		case errors.As(err, &te):
			return apierr.Validation([]apierr.FieldError{{Pointer: "/" + strings.ReplaceAll(te.Field, ".", "/"), Code: "WRONG_TYPE", Detail: "Expected " + te.Type.String() + "."}})
		case strings.HasPrefix(err.Error(), "json: unknown field"):
			f := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
			return apierr.Validation([]apierr.FieldError{{Pointer: "/" + f, Code: "UNKNOWN_FIELD", Detail: "This field is not accepted here."}})
		case errors.As(err, &se), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
			return apierr.BadRequest(apierr.CodeBadJSON, "The request body is not valid JSON.")
		default:
			return apierr.BadRequest(apierr.CodeBadJSON, "The request body could not be read.")
		}
	}
	if dec.More() {
		return apierr.BadRequest(apierr.CodeBadJSON, "Send exactly one JSON object.")
	}
	return nil
}

// can enforces a global permission; returns false after writing 403.
func (s *Server) can(w http.ResponseWriter, r *http.Request, action string) bool {
	if authz.Can(authz.ActorFrom(r.Context()), action, authz.Any) {
		return true
	}
	s.Audit.Record(r.Context(), "authz.denied", "denied", "", map[string]any{"action": action, "path": r.URL.Path})
	s.fail(w, r, apierr.Forbidden("Your role cannot do this. Ask an admin if you need access."))
	return false
}

func pageParams(r *http.Request) (int, string) {
	n, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if n <= 0 {
		n = 50
	}
	if n > 200 {
		n = 200
	}
	return n, r.URL.Query().Get("page_token")
}

func boolParam(r *http.Request, name string) *bool {
	switch r.URL.Query().Get(name) {
	case "true":
		t := true
		return &t
	case "false":
		f := false
		return &f
	}
	return nil
}

func ifMatch(r *http.Request) (string, error) {
	v := r.Header.Get("If-Match")
	if v == "" {
		return "", apierr.New(http.StatusPreconditionRequired, apierr.CodePreconditionReq, "Send If-Match with the item's etag so concurrent edits are not lost.")
	}
	return v, nil
}
