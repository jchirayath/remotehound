// @feature:sessions
package device

import (
	"testing"
	"time"

	"github.com/jchirayath/remotehound/internal/core/authz"
	"github.com/jchirayath/remotehound/internal/model"
)

func TestSessionViewFlagsDeletedDevice(t *testing.T) {
	now := time.Now().UTC()
	a := &authz.Actor{UserID: "usr_a"}
	ss := &model.Session{Meta: model.Meta{ID: "ses_1"}, DeviceID: "dev_1", UserID: "usr_a", StartedAt: now}
	st := &model.State{Devices: map[string]*model.Device{"dev_1": {Meta: model.Meta{ID: "dev_1"}, Name: "laptop"}}}
	if v := toSessionView(a, ss, st, now); v.DeviceDeleted || v.DeviceName != "laptop" {
		t.Fatalf("live device: %+v", v)
	}
	delete(st.Devices, "dev_1")
	if v := toSessionView(a, ss, st, now); !v.DeviceDeleted || v.DeviceName != "(deleted device)" {
		t.Fatalf("deleted device: %+v", v)
	}
	st.Enrollments = map[string]*model.Enrollment{"enr_1": {Meta: model.Meta{ID: "enr_1"}, Name: "laptop", DeviceID: "dev_1"}}
	if v := toSessionView(a, ss, st, now); !v.DeviceDeleted || v.DeviceName != "laptop (deleted device)" {
		t.Fatalf("deleted device keeps its enrollment name: %+v", v)
	}
}
