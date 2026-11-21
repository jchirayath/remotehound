package device

import (
	"strings"

	"github.com/jchirayath/remotehound/internal/model"
)

// IdentityWarning flags a device that may not be the machine its name says:
// the enrolment command was run on the wrong machine, or one machine was
// enrolled twice. Advisory only: nothing is blocked.
type IdentityWarning struct {
	Code    string `json:"code"`    // NAME_OS_MISMATCH | DUPLICATE_HOST
	Message string `json:"message"` // one sentence for people
	// DUPLICATE_HOST: the other device that reports the same machine.
	OtherDeviceID   string `json:"other_device_id,omitempty"`
	OtherDeviceName string `json:"other_device_name,omitempty"`
}

// Words in a device name that say which OS it runs.
var osWords = map[string]string{
	"mac": "macos", "macos": "macos", "osx": "macos", "macbook": "macos", "imac": "macos", "macmini": "macos", "darwin": "macos",
	"linux": "linux", "ubuntu": "linux", "debian": "linux", "fedora": "linux", "alpine": "linux", "centos": "linux",
	"rhel": "linux", "raspbian": "linux", "raspberrypi": "linux", "arch": "linux", "mint": "linux",
	"windows": "windows", "win": "windows", "win10": "windows", "win11": "windows", "avd": "windows",
}

var osNames = map[string]string{"macos": "macOS", "linux": "Linux", "windows": "Windows"}

// namedOSes returns the OS families a name mentions ("office-linux" → linux).
func namedOSes(name string) map[string]bool {
	out := map[string]bool{}
	for _, tok := range strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if fam, ok := osWords[tok]; ok {
			out[fam] = true
		}
	}
	return out
}

// nameOSWarning: the name says one OS, the machine reports another.
func nameOSWarning(d *model.Device) *IdentityWarning {
	reported, known := osNames[d.OS]
	if !known {
		return nil
	}
	named := namedOSes(d.Name)
	if len(named) == 0 || named[d.OS] {
		return nil
	}
	var said string
	for fam := range named {
		said = osNames[fam]
	}
	host := ""
	if d.Hostname != "" {
		host = " (hostname " + d.Hostname + ")"
	}
	return &IdentityWarning{Code: "NAME_OS_MISMATCH",
		Message: "The name says " + said + ", but this machine reports " + reported + host + ". The enrolment command may have been run on the wrong machine."}
}

// hostKey identifies "the same machine" for duplicate detection.
func hostKey(d *model.Device) string {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d.Hostname), ".local"))
	if h == "" || h == "device" || h == "localhost" {
		return ""
	}
	return d.OS + "|" + h
}

// identityWarnings for d, given the other devices the viewer can see.
func identityWarnings(d *model.Device, others []*model.Device) []IdentityWarning {
	out := []IdentityWarning{}
	if w := nameOSWarning(d); w != nil {
		out = append(out, *w)
	}
	if k := hostKey(d); k != "" {
		for _, o := range others {
			if o.ID != d.ID && hostKey(o) == k {
				out = append(out, IdentityWarning{Code: "DUPLICATE_HOST", OtherDeviceID: o.ID, OtherDeviceName: o.Name,
					Message: "\"" + o.Name + "\" reports the same machine (" + d.Hostname + ", " + osNames[d.OS] + "). One machine may have been enrolled twice; delete the entry you no longer use."})
				break
			}
		}
	}
	return out
}

// RedeemWarnings returns the codes of the warnings a just-enrolled device
// raises, for the audit record.
func RedeemWarnings(d *model.Device, all map[string]*model.Device) []string {
	others := make([]*model.Device, 0, len(all))
	for _, o := range all {
		others = append(others, o)
	}
	var codes []string
	for _, w := range identityWarnings(d, others) {
		codes = append(codes, w.Code)
	}
	return codes
}
