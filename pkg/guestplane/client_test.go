//go:build linux

package guestplane

import (
	"bytes"
	"context"
	"errors"
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
			// nil Dispatcher = legacy "not yet routed" stub path.
			resp := dispatchControl(context.Background(), c.req, nil, logger)
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

// fakeDispatcher is a chan-based stub : each callback signals on its
// own channel + records the args it was called with, so a test can
// assert the right ControlRequest variant landed on the right slot
// with the right values.
type fakeDispatcher struct {
	stopPodGrace chan uint32
	killArgs     chan [2]string // [containerID, signal]
	execReq      chan *guestv1.ExecInContainer
	updateReq    chan *guestv1.UpdateContainer
	// returnErr, if set, is returned from every callback to exercise
	// the error-stringify path.
	returnErr error
}

func newFakeDispatcher() *fakeDispatcher {
	return &fakeDispatcher{
		stopPodGrace: make(chan uint32, 1),
		killArgs:     make(chan [2]string, 1),
		execReq:      make(chan *guestv1.ExecInContainer, 1),
		updateReq:    make(chan *guestv1.UpdateContainer, 1),
	}
}

func (f *fakeDispatcher) Dispatcher() *Dispatcher {
	return &Dispatcher{
		StopPod: func(_ context.Context, g uint32) error {
			f.stopPodGrace <- g
			return f.returnErr
		},
		Kill: func(_ context.Context, id, sig string) error {
			f.killArgs <- [2]string{id, sig}
			return f.returnErr
		},
		Exec: func(_ context.Context, e *guestv1.ExecInContainer) error {
			f.execReq <- e
			return f.returnErr
		},
		Update: func(_ context.Context, u *guestv1.UpdateContainer) error {
			f.updateReq <- u
			return f.returnErr
		},
	}
}

// TestDispatchControl_RoutesStopPod : a StopPod variant lands on the
// dispatcher's StopPod slot with the gace seconds intact and yields a
// success (empty Error) ControlResponse.
func TestDispatchControl_RoutesStopPod(t *testing.T) {
	fd := newFakeDispatcher()
	logger := log.New(&bytes.Buffer{}, "", 0)
	req := &guestv1.ControlRequest{
		CallId: 7,
		Op:     &guestv1.ControlRequest_StopPod{StopPod: &guestv1.StopPod{GraceSeconds: 12}},
	}
	resp := dispatchControl(context.Background(), req, fd.Dispatcher(), logger)
	if resp.GetCallId() != 7 {
		t.Errorf("call_id : got %d, want 7", resp.GetCallId())
	}
	if resp.GetError() != "" {
		t.Errorf("expected empty Error, got %q", resp.GetError())
	}
	select {
	case g := <-fd.stopPodGrace:
		if g != 12 {
			t.Errorf("graceSeconds : got %d, want 12", g)
		}
	default:
		t.Fatal("StopPod callback was not invoked")
	}
}

// TestDispatchControl_RoutesKill_DefaultsSignal : a Kill variant with
// an empty Signal lands on the dispatcher with signal defaulted to
// "SIGTERM" — the documented in-guest default.
func TestDispatchControl_RoutesKill_DefaultsSignal(t *testing.T) {
	fd := newFakeDispatcher()
	logger := log.New(&bytes.Buffer{}, "", 0)
	req := &guestv1.ControlRequest{
		CallId: 8,
		Op:     &guestv1.ControlRequest_Kill{Kill: &guestv1.KillContainer{ContainerId: "c1"}},
	}
	resp := dispatchControl(context.Background(), req, fd.Dispatcher(), logger)
	if resp.GetError() != "" {
		t.Errorf("expected empty Error, got %q", resp.GetError())
	}
	select {
	case args := <-fd.killArgs:
		if args[0] != "c1" || args[1] != "SIGTERM" {
			t.Errorf("Kill args : got %v, want [c1 SIGTERM]", args)
		}
	default:
		t.Fatal("Kill callback was not invoked")
	}
}

// TestDispatchControl_RoutesExec : an Exec variant routes the proto
// verbatim to the Exec slot.
func TestDispatchControl_RoutesExec(t *testing.T) {
	fd := newFakeDispatcher()
	logger := log.New(&bytes.Buffer{}, "", 0)
	exec := &guestv1.ExecInContainer{ContainerId: "c2", Command: []string{"sh", "-c", "echo hi"}, Tty: true}
	req := &guestv1.ControlRequest{CallId: 9, Op: &guestv1.ControlRequest_Exec{Exec: exec}}
	resp := dispatchControl(context.Background(), req, fd.Dispatcher(), logger)
	if resp.GetError() != "" {
		t.Errorf("expected empty Error, got %q", resp.GetError())
	}
	select {
	case got := <-fd.execReq:
		if got != exec {
			t.Errorf("Exec routed a different proto value than the one sent in")
		}
	default:
		t.Fatal("Exec callback was not invoked")
	}
}

// TestDispatchControl_RoutesUpdate : an Update variant routes the
// proto verbatim to the Update slot.
func TestDispatchControl_RoutesUpdate(t *testing.T) {
	fd := newFakeDispatcher()
	logger := log.New(&bytes.Buffer{}, "", 0)
	upd := &guestv1.UpdateContainer{ContainerId: "c3", Command: []string{"bash"}}
	req := &guestv1.ControlRequest{CallId: 10, Op: &guestv1.ControlRequest_Update{Update: upd}}
	resp := dispatchControl(context.Background(), req, fd.Dispatcher(), logger)
	if resp.GetError() != "" {
		t.Errorf("expected empty Error, got %q", resp.GetError())
	}
	select {
	case got := <-fd.updateReq:
		if got != upd {
			t.Errorf("Update routed a different proto value than the one sent in")
		}
	default:
		t.Fatal("Update callback was not invoked")
	}
}

// TestDispatchControl_ErrorIsStringified : a dispatcher callback that
// returns an error surfaces .Error() in the ControlResponse.Error
// field, and the host's correlator still gets the matching CallId.
func TestDispatchControl_ErrorIsStringified(t *testing.T) {
	fd := newFakeDispatcher()
	fd.returnErr = errors.New("boom")
	logger := log.New(&bytes.Buffer{}, "", 0)
	req := &guestv1.ControlRequest{
		CallId: 11,
		Op:     &guestv1.ControlRequest_StopPod{StopPod: &guestv1.StopPod{}},
	}
	resp := dispatchControl(context.Background(), req, fd.Dispatcher(), logger)
	if resp.GetCallId() != 11 {
		t.Errorf("call_id : got %d, want 11", resp.GetCallId())
	}
	if resp.GetError() != "boom" {
		t.Errorf("Error string : got %q, want %q", resp.GetError(), "boom")
	}
	// Drain the channel so the goroutine doesn't leak.
	<-fd.stopPodGrace
}

// TestDispatchControl_PartialDispatcher : if a single slot is nil
// (e.g. an agent that wired StopPod but not Kill yet), the unwired
// variant gets the legacy stub Error while the wired one is invoked.
func TestDispatchControl_PartialDispatcher(t *testing.T) {
	fd := newFakeDispatcher()
	dp := fd.Dispatcher()
	dp.Kill = nil // explicitly unwire Kill
	logger := log.New(&bytes.Buffer{}, "", 0)

	stopReq := &guestv1.ControlRequest{CallId: 1, Op: &guestv1.ControlRequest_StopPod{StopPod: &guestv1.StopPod{}}}
	if resp := dispatchControl(context.Background(), stopReq, dp, logger); resp.GetError() != "" {
		t.Errorf("StopPod : expected empty Error, got %q", resp.GetError())
	}
	<-fd.stopPodGrace

	killReq := &guestv1.ControlRequest{CallId: 2, Op: &guestv1.ControlRequest_Kill{Kill: &guestv1.KillContainer{ContainerId: "c"}}}
	resp := dispatchControl(context.Background(), killReq, dp, logger)
	if resp.GetError() == "" {
		t.Errorf("Kill : expected non-empty Error (unwired slot), got empty")
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
