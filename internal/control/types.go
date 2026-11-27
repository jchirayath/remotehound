// Package control is rh-control: the small, optional helper that lets the
// Services screen start, stop and restart the bundle's own containers and read
// their logs — and nothing else.
//
// WHY A SEPARATE PROCESS. Docker control needs the Docker socket, and the
// socket is root on the host. RemoteHound itself faces the internet (sign-in,
// enrollment, the Guacamole proxy); giving it the socket would turn any bug in
// it into a takeover of every container on the machine. The helper instead:
//
//   - has no published port and sits on a network only remotehound can reach;
//   - answers only requests carrying the shared RH_CONTROL_TOKEN;
//   - acts ONLY on containers the operator labeled
//     io.remotehound.control.service=<name>, with ONLY the actions listed in
//     io.remotehound.control.actions (subset of start, stop, restart, logs);
//   - returns a fixed, allowlisted view of each container — never its
//     environment, mounts or command line, which is where secrets live.
//
// RemoteHound authorizes the person (admin only), audits the action and calls
// the helper; the helper enforces the label allowlist again on its side, so a
// compromised RemoteHound still cannot touch an unlabeled container.
//
// See docs/adr/0004-rh-control.md and docs/THREAT_MODEL.md (TB-6).
package control

import "time"

// Container labels the operator sets in compose.
const (
	LabelService = "io.remotehound.control.service" // the name the UI shows, e.g. "guacamole"
	LabelActions = "io.remotehound.control.actions" // comma-separated subset of AllActions
)

// Actions.
const (
	ActionStart   = "start"
	ActionStop    = "stop"
	ActionRestart = "restart"
	ActionLogs    = "logs"
)

// AllActions is every action the helper knows. Anything else in a label is ignored.
var AllActions = []string{ActionStart, ActionStop, ActionRestart, ActionLogs}

// Container is the allowlisted view of one controllable container.
type Container struct {
	Service      string    `json:"service"`
	Name         string    `json:"name"`
	Image        string    `json:"image"`
	State        string    `json:"state"`            // created|running|paused|restarting|removing|exited|dead
	Health       string    `json:"health,omitempty"` // starting|healthy|unhealthy ("" = no healthcheck)
	StartedAt    time.Time `json:"started_at,omitzero"`
	FinishedAt   time.Time `json:"finished_at,omitzero"`
	RestartCount int       `json:"restart_count"`
	ExitCode     int       `json:"exit_code"`
	OOMKilled    bool      `json:"oom_killed,omitempty"`
	Error        string    `json:"error,omitempty"` // Docker's last start error
	Actions      []string  `json:"actions"`
}

// LogLine is one line of container output.
type LogLine struct {
	Time   time.Time `json:"time,omitzero"`
	Stream string    `json:"stream"` // stdout|stderr
	Text   string    `json:"text"`
}

// Limits.
const (
	MaxTail     = 1000
	DefaultTail = 200
	maxLineLen  = 4096
)
