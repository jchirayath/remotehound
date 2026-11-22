// Package apierr is CORE-7: typed errors with stable codes, rendered as RFC 9457
// problem+json (API-5).
//
// Contract: handlers return *Error (or wrap one); Write renders it with the
// request ID and never leaks internal detail — an untyped error becomes a
// generic 500 INTERNAL and its message goes only to the log. Codes are
// DOMAIN_REASON and never change once shipped; the UI help registry maps each
// code to "how to fix it" text (HELP-3).
package apierr

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Stable error codes. Add, never rename.
const (
	CodeValidation       = "VALIDATION_FAILED"
	CodeBadJSON          = "REQUEST_MALFORMED"
	CodeUnauthenticated  = "AUTH_REQUIRED"
	CodeForbidden        = "AUTH_FORBIDDEN"
	CodeCSRF             = "AUTH_CSRF_FAILED"
	CodeNotFound         = "NOT_FOUND"
	CodePrecondition     = "PRECONDITION_FAILED"
	CodePreconditionReq  = "PRECONDITION_REQUIRED"
	CodeRateLimited      = "RATE_LIMITED"
	CodeInternal         = "INTERNAL"
	CodeUnavailable      = "SERVICE_UNAVAILABLE"
	CodeDeviceNotFound   = "DEVICE_NOT_FOUND"
	CodeDeviceOffline    = "DEVICE_OFFLINE"
	CodeDeviceDisabled   = "DEVICE_DISABLED"
	CodeServiceMissing   = "SERVICE_NOT_CONFIGURED"
	CodeServiceNotFwd    = "SERVICE_NOT_FORWARDED"
	CodeGuacUnavailable  = "GUAC_UNAVAILABLE"
	CodeEnrollInvalid    = "ENROLL_CODE_INVALID"
	CodeEnrollUsed       = "ENROLL_CODE_USED"
	CodeEnrollExpired    = "ENROLL_CODE_EXPIRED"
	CodeEnrollWrongOS    = "ENROLL_WRONG_OS"
	CodeEnrollKeyInvalid = "ENROLL_KEY_INVALID"
	// CodeEnrollWrongMethod: an attended code used with a script (ADR-0005); not consumed.
	CodeEnrollWrongMethod = "ENROLL_WRONG_METHOD"
	CodeGroupNotEmpty     = "GROUP_NOT_EMPTY"
	CodeGroupNotFound     = "GROUP_NOT_FOUND"
	CodeUserNotFound      = "USER_NOT_FOUND"
	CodeUserExists        = "USER_EXISTS"
	CodeLastAdmin         = "LAST_ADMIN"
	CodeSessionNotFound   = "SESSION_NOT_FOUND"
	CodeJobNotFound       = "JOB_NOT_FOUND"
	CodeRecordingMissing  = "RECORDING_NOT_FOUND"
	CodeProxyIdentity     = "PROXY_IDENTITY_MISSING"
	CodeControlOff        = "CONTROL_UNAVAILABLE"
	CodeControlDenied     = "CONTROL_ACTION_NOT_ALLOWED"
	CodeControlTarget     = "CONTROL_TARGET_NOT_FOUND"
	CodeCredsRequired     = "CREDENTIALS_REQUIRED"
	CodePublicURLInvalid  = "SETTINGS_PUBLIC_URL_INVALID"
)

// FieldError points at one invalid input field (JSON Pointer).
type FieldError struct {
	Pointer string `json:"pointer"`
	Code    string `json:"code"`
	Detail  string `json:"detail"`
}

// Error is a client-safe error.
type Error struct {
	Status int
	Code   string
	Title  string
	Detail string
	Fields []FieldError
	Cause  error // logged, never sent
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return e.Code + ": " + e.Detail + ": " + e.Cause.Error()
	}
	return e.Code + ": " + e.Detail
}

// ErrorCode lets logx record error.type without importing this package.
func (e *Error) ErrorCode() string { return e.Code }

// Unwrap exposes the cause to errors.Is/As.
func (e *Error) Unwrap() error { return e.Cause }

// New builds an error.
func New(status int, code, detail string) *Error {
	return &Error{Status: status, Code: code, Title: http.StatusText(status), Detail: detail}
}

// Wrap attaches an internal cause (logged only).
func (e *Error) Wrap(cause error) *Error { c := *e; c.Cause = cause; return &c }

// Convenience constructors.
func BadRequest(code, detail string) *Error { return New(http.StatusBadRequest, code, detail) }
func NotFound(code, detail string) *Error   { return New(http.StatusNotFound, code, detail) }
func Conflict(code, detail string) *Error   { return New(http.StatusConflict, code, detail) }
func Forbidden(detail string) *Error        { return New(http.StatusForbidden, CodeForbidden, detail) }
func Unauthenticated() *Error {
	return New(http.StatusUnauthorized, CodeUnauthenticated, "Sign in to continue.")
}
func Internal(cause error) *Error {
	return New(http.StatusInternalServerError, CodeInternal, "Something went wrong on our side. Quote the request ID if you report it.").Wrap(cause)
}
func Validation(fields []FieldError) *Error {
	e := New(http.StatusBadRequest, CodeValidation, "Some fields need attention.")
	e.Fields = fields
	return e
}
func Precondition() *Error {
	return New(http.StatusPreconditionFailed, CodePrecondition, "Someone else changed this since you loaded it. Reload and try again.")
}

// As extracts *Error from err, mapping anything else to Internal.
func As(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return Internal(err)
}

// problem is the RFC 9457 wire shape.
type problem struct {
	Type      string       `json:"type"`
	Title     string       `json:"title"`
	Status    int          `json:"status"`
	Detail    string       `json:"detail,omitempty"`
	Instance  string       `json:"instance,omitempty"`
	Code      string       `json:"code"`
	RequestID string       `json:"request_id"`
	Errors    []FieldError `json:"errors,omitempty"`
}

// Write renders err as problem+json. requestID comes from the request scope.
func Write(w http.ResponseWriter, r *http.Request, requestID string, err error) {
	e := As(err)
	p := problem{
		Type:      "https://github.com/jchirayath/remotehound/blob/main/docs/user/errors.md#" + e.Code,
		Title:     e.Title,
		Status:    e.Status,
		Detail:    e.Detail,
		Code:      e.Code,
		RequestID: requestID,
		Errors:    e.Fields,
	}
	if r != nil {
		p.Instance = r.URL.Path
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(p) // client went away; nothing useful to do
}
