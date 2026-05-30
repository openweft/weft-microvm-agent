package mesh

import (
	"encoding/json"
	"testing"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

func validUpdate() []byte {
	wg := pod.WireGuard{
		Interface:  "wg0",
		PrivateKey: "SPNDBl7lCblAAn1AICFvIGD2PIjzNftxKbmOLd2IZ1o=",
		Address:    "10.9.0.3/24",
		Peers: []pod.WGPeer{{
			PublicKey:  "n65/cbhW0nKpOoz7yNO+QbP9k6SHvKAQdEm4PPBrQ3E=",
			Endpoint:   "10.9.0.2:51820",
			AllowedIPs: []string{"10.9.0.2/32"},
		}},
	}
	b, _ := json.Marshal(wg)
	return b
}

func TestHandleMessage_AppliesDecodedConfig(t *testing.T) {
	var got *pod.WireGuard
	err := HandleMessage(validUpdate(), func(wg *pod.WireGuard) error {
		got = wg
		return nil
	})
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	if got == nil {
		t.Fatal("apply was not called")
	}
	if got.Address != "10.9.0.3/24" || len(got.Peers) != 1 {
		t.Errorf("decoded config wrong: %+v", got)
	}
	if got.Peers[0].Endpoint != "10.9.0.2:51820" {
		t.Errorf("peer endpoint = %s", got.Peers[0].Endpoint)
	}
}

func TestHandleMessage_RejectsInvalidJSON(t *testing.T) {
	called := false
	err := HandleMessage([]byte("{not json"), func(*pod.WireGuard) error { called = true; return nil })
	if err == nil {
		t.Error("expected decode error")
	}
	if called {
		t.Error("apply must not run on bad JSON")
	}
}

func TestHandleMessage_RejectsIncompleteConfig(t *testing.T) {
	// Missing private_key / address → Validate fails, apply must not run.
	bad, _ := json.Marshal(pod.WireGuard{Interface: "wg0"})
	called := false
	if err := HandleMessage(bad, func(*pod.WireGuard) error { called = true; return nil }); err == nil {
		t.Error("expected validation error")
	}
	if called {
		t.Error("apply must not run on invalid config")
	}
}

func TestSubject(t *testing.T) {
	if Subject("vm-123") != "weft.mesh.vm-123" {
		t.Errorf("Subject = %q", Subject("vm-123"))
	}
}
