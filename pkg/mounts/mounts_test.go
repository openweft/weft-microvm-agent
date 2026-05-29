package mounts

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

func TestSubject(t *testing.T) {
	if got := Subject("vm-42"); got != "weft.mounts.vm-42" {
		t.Errorf("Subject = %q", got)
	}
}

func cubefsMount() pod.ShareMount {
	return pod.ShareMount{
		ID:         "team-data",
		MountPoint: "/run/weft/shares/team-data",
		CubeFS: &pod.CubeFSMount{
			Volume:  "team-data",
			Masters: []string{"10.9.0.1:17010"},
			Owner:   "team-alpha",
		},
	}
}

func TestHandleMessage_Mount(t *testing.T) {
	data, _ := json.Marshal(cubefsMount())

	var got pod.ShareMount
	called := false
	err := HandleMessage(data, func(m pod.ShareMount) error { got = m; called = true; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !called || got.ID != "team-data" || got.CubeFS == nil || got.CubeFS.Volume != "team-data" {
		t.Errorf("apply got %+v (called=%v)", got, called)
	}
}

func TestHandleMessage_Unmount(t *testing.T) {
	data, _ := json.Marshal(pod.ShareMount{ID: "team-data", Action: pod.MountActionUnmount, MountPoint: "/run/weft/shares/team-data"})
	var got pod.ShareMount
	if err := HandleMessage(data, func(m pod.ShareMount) error { got = m; return nil }); err != nil {
		t.Fatal(err)
	}
	if got.Action != pod.MountActionUnmount {
		t.Errorf("action = %q", got.Action)
	}
}

func TestHandleMessage_BadJSON(t *testing.T) {
	err := HandleMessage([]byte("{not json"), func(pod.ShareMount) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "decode mount update") {
		t.Fatalf("got %v", err)
	}
}

func TestHandleMessage_Invalid(t *testing.T) {
	// Missing id → ShareMount.Validate fails, apply must not run.
	m := cubefsMount()
	m.ID = ""
	data, _ := json.Marshal(m)
	ran := false
	err := HandleMessage(data, func(pod.ShareMount) error { ran = true; return nil })
	if err == nil || !strings.Contains(err.Error(), "invalid mount update") {
		t.Fatalf("got %v", err)
	}
	if ran {
		t.Error("apply ran on an invalid update")
	}
}
