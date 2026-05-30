package cubefs

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

func TestClientConfig(t *testing.T) {
	spec := pod.ShareMount{
		ID:         "team-data",
		MountPoint: "/run/weft/shares/team-data",
		Readonly:   true,
		CubeFS: &pod.CubeFSMount{
			Volume:    "team-data",
			Masters:   []string{"10.9.0.1:17010", "10.9.0.2:17010"},
			Owner:     "team-alpha",
			AccessKey: "AK",
			SecretKey: "SK",
			SubDir:    "/datasets",
		},
	}
	b, err := clientConfig(spec, "/run/weft/cubefs/team-data/log")
	if err != nil {
		t.Fatal(err)
	}
	var got clientCfg
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.VolName != "team-data" || got.Owner != "team-alpha" {
		t.Errorf("vol/owner = %q/%q", got.VolName, got.Owner)
	}
	if got.MasterAddr != "10.9.0.1:17010,10.9.0.2:17010" {
		t.Errorf("masterAddr = %q (want comma-joined)", got.MasterAddr)
	}
	if got.MountPoint != spec.MountPoint || got.SubDir != "/datasets" || !got.ReadOnly {
		t.Errorf("cfg = %+v", got)
	}
	if got.AccessKey != "AK" || got.SecretKey != "SK" {
		t.Errorf("keys not propagated: %+v", got)
	}
}

func TestMount_RejectsNonCubeFS(t *testing.T) {
	_, err := Mount(pod.ShareMount{ID: "x", Backend: "nfs", MountPoint: "/mnt/x"})
	if err == nil || !strings.Contains(err.Error(), "unsupported backend") {
		t.Fatalf("got %v", err)
	}
}
