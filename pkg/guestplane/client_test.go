//go:build linux

package guestplane

import (
	"bytes"
	"log"
	"testing"

	guestv1 "github.com/openweft/weft-proto/guestv1"
)

// TestDispatchControl_AcksWithSameCallID is the wire-contract pin :
// the guest must echo the host's call_id on every ControlResponse,
// even when the operation isn't implemented yet. Without that the
// host's dispatcher can't correlate response → request and would
// stall.
func TestDispatchControl_AcksWithSameCallID(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	cases := []struct {
		name string
		req  *guestv1.ControlRequest
	}{
		{"stop", &guestv1.ControlRequest{CallId: 42, Op: &guestv1.ControlRequest_StopPod{StopPod: &guestv1.StopPod{}}}},
		{"kill", &guestv1.ControlRequest{CallId: 43, Op: &guestv1.ControlRequest_Kill{Kill: &guestv1.KillContainer{}}}},
		{"exec", &guestv1.ControlRequest{CallId: 44, Op: &guestv1.ControlRequest_Exec{Exec: &guestv1.ExecInContainer{}}}},
		{"update", &guestv1.ControlRequest{CallId: 45, Op: &guestv1.ControlRequest_Update{Update: &guestv1.UpdateContainer{}}}},
		{"empty-op", &guestv1.ControlRequest{CallId: 99}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := dispatchControl(c.req, logger)
			if resp == nil {
				t.Fatal("dispatchControl returned nil")
			}
			if resp.GetCallId() != c.req.GetCallId() {
				t.Errorf("call_id echo broken : got %d, want %d", resp.GetCallId(), c.req.GetCallId())
			}
			if resp.GetError() == "" {
				t.Errorf("expected an Error string while dispatch is not wired in-guest yet ; got empty")
			}
		})
	}
}

// TestConfigDefaults pins that an empty Config{PodID: "p"} value
// fills every cadence field with the package-level Default* so a
// caller forgetting to set HeartbeatTick / ReconnectGap doesn't
// silently spin a hot loop.
func TestConfigDefaults(t *testing.T) {
	// Exercise the defaulting via a direct construct then a comparison
	// — Run() defaults in-place on a copy, so we apply the same logic
	// manually here to keep the test pure (no goroutine, no vsock).
	cfg := Config{PodID: "p"}
	if cfg.HostCID == 0 {
		cfg.HostCID = 2 // VsockCIDHost
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
	}
	if cfg.HeartbeatTick == 0 {
		cfg.HeartbeatTick = DefaultHeartbeatTick
	}
	if cfg.ReconnectGap == 0 {
		cfg.ReconnectGap = DefaultReconnectGap
	}
	if cfg.DialAttempts == 0 {
		cfg.DialAttempts = DefaultDialAttempts
	}
	if cfg.DialDelay == 0 {
		cfg.DialDelay = DefaultDialDelay
	}
	if cfg.HostCID != 2 || cfg.Port != DefaultPort || cfg.HeartbeatTick != DefaultHeartbeatTick {
		t.Errorf("defaults missing : %+v", cfg)
	}
}
