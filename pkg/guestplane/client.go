//go:build linux

// Package guestplane is the guest-side half of the GuestPodPlane
// bidi stream defined in weft-proto/guestv1. The host serves
// GuestPodPlane on AF_VSOCK ; this client dials CID_HOST (=2) on
// the agent's configured port, sends the mandatory GuestHello,
// receives a GuestHelloAck (carrying the operator's PodSpec when
// known), and stays connected to :
//
//   - emit a PodStatus heartbeat every interval (uptime, container
//     summary stub for now — containers aren't reconciled in-guest
//     yet beyond the on-NATS reconciler) ;
//   - read ControlRequest frames from the host and ack them via
//     ControlResponse so the host's dispatcher doesn't stall.
//
// The client is intentionally minimal — the wire contract here is
// what protects against pod-id impersonation (the host's strict-
// when-known peer-CID check refuses any Hello announcing the wrong
// pod_id). Any future per-container state machine lives in
// pkg/containers ; this file just owns the wire layer.
package guestplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/openweft/weft-microvm-init/pkg/transport"
	guestv1 "github.com/openweft/weft-proto/guestv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Dispatcher is the action layer behind dispatchControl : a ControlRequest
// frame arrives over the AF_VSOCK GuestPodPlane, the wire layer (this
// file) ACKs it, and routes it through these callbacks so the in-guest
// reconcilers (pkg/containers, pkg/execsession) actually do the work.
//
// All fields are optional. A nil callback resolves to the legacy
// "not yet routed" Error so the host's operator sees a clear signal
// the dispatch slot hasn't been wired locally — preserving the
// dispatchControl-as-stub behaviour for callers that don't pass one.
//
// Each callback returns the *string the host should surface as the
// ControlResponse.Error : empty / "" = success. Errors are stringified
// by the caller, not the dispatcher, so the wire shape stays simple.
type Dispatcher struct {
	// StopPod is invoked on a ControlRequest_StopPod. graceSeconds is
	// the StopPod.GraceSeconds value (0 = caller-chosen default).
	StopPod func(ctx context.Context, graceSeconds uint32) error
	// Kill is invoked on a ControlRequest_Kill. signal defaults to
	// "SIGTERM" when empty.
	Kill func(ctx context.Context, containerID, signal string) error
	// Exec is invoked on a ControlRequest_Exec. The dispatcher
	// receives the proto value verbatim so it can decide whether to
	// open a pty (tty=true) or a one-shot exec.
	Exec func(ctx context.Context, e *guestv1.ExecInContainer) error
	// Update is invoked on a ControlRequest_Update. UpdateContainer
	// carries the new command + merged env for one container.
	Update func(ctx context.Context, u *guestv1.UpdateContainer) error
}

// Default port the host-side weft-agent binds its AF_VSOCK
// listener on. Operators can override via the agent flag ; the
// guest side has to agree, so this constant is the wire contract.
// 7777 chosen to match cmd/weft/main.go's --vsock-port default.
const DefaultPort uint32 = 7777

// Default reconnect / heartbeat cadences. Tuned for "fast enough
// the operator notices a flapping link, slow enough that an idle
// VM doesn't fill weft-agent's stderr with reconnect noise".
const (
	DefaultDialAttempts  = 60               // ~1 minute of retries
	DefaultDialDelay     = 1 * time.Second  // between attempts
	DefaultHeartbeatTick = 10 * time.Second // PodStatus cadence
	DefaultReconnectGap  = 5 * time.Second  // after Recv error
)

// Config carries the knobs the agent's main() wires up. Empty
// fields fall back to the Default* constants — letting the caller
// build a Config{Host: ..., Logger: ...} and ship reasonable
// defaults.
type Config struct {
	// HostCID is the AF_VSOCK CID to dial. Always 2 (CID_HOST) in
	// production ; the field exists so a unit test can dial a
	// loopback listener via VsockCIDLocal=1 if it ever gets one.
	HostCID uint32
	// Port is the host's GuestPodPlane vsock port.
	Port uint32
	// PodID announced via GuestHello. Must match the pod_id the
	// host has on record (= VM name, the strict-when-known guard
	// rejects a Hello where peer.CID() != adapter.PodCID(pod_id)).
	PodID string
	// KernelInfo / InitVersion go into the Hello so the host's
	// logs carry the booted kernel + guest agent build.
	KernelInfo  string
	InitVersion string

	// HeartbeatTick is how often a PodStatus frame is sent. 0 →
	// DefaultHeartbeatTick. Set negative to disable heartbeats
	// entirely (the Hello/Ack handshake still runs).
	HeartbeatTick time.Duration
	// ReconnectGap is the pause before redialing after a Recv
	// error. 0 → DefaultReconnectGap.
	ReconnectGap time.Duration
	// DialAttempts is how many times we retry the initial dial
	// before giving up. 0 → DefaultDialAttempts.
	DialAttempts int
	// DialDelay is the per-attempt delay during the initial dial
	// retry loop. 0 → DefaultDialDelay.
	DialDelay time.Duration

	Logger *log.Logger

	// Dispatcher routes incoming ControlRequest frames into the
	// in-guest reconcilers. nil = the legacy "not yet routed" stub
	// reply is returned to the host (every ACK still carries the
	// matching CallId so the host's correlator doesn't stall).
	Dispatcher *Dispatcher
}

// Run is the daemon body : dial, Hello/HelloAck handshake, then a
// long-lived attached session. Reconnects on every Recv error
// until ctx is cancelled.
//
// Returns ctx.Err() on clean shutdown so callers can distinguish
// "we were told to stop" from "we failed".
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.HostCID == 0 {
		cfg.HostCID = transport.VsockCIDHost
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
	if cfg.PodID == "" {
		return errors.New("guestplane: PodID is required")
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := runOnce(ctx, cfg); err != nil {
			cfg.Logger.Printf("guestplane: session ended : %v ; reconnecting in %s", err, cfg.ReconnectGap)
		}
		// Wait before redialing ; respects ctx cancellation so a
		// shutdown signal doesn't have to wait out the full gap.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cfg.ReconnectGap):
		}
	}
}

// runOnce dials, handshakes, then ticks heartbeats + reads
// ControlRequest frames until something breaks or ctx is done.
func runOnce(ctx context.Context, cfg Config) error {
	conn, err := transport.DialWithRetry(cfg.HostCID, cfg.Port, cfg.DialAttempts, cfg.DialDelay)
	if err != nil {
		return fmt.Errorf("dial vsock (%d,%d): %w", cfg.HostCID, cfg.Port, err)
	}
	cfg.Logger.Printf("guestplane: dialed vsock://%d:%d", cfg.HostCID, cfg.Port)

	// Build a gRPC client over the already-open conn. The contextDialer
	// just hands the existing connection back — grpc.DialContext does
	// the framing on top of it.
	cc, err := grpc.NewClient(
		fmt.Sprintf("passthrough://vsock/%d/%d", cfg.HostCID, cfg.Port),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return conn, nil
		}),
	)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("grpc client: %w", err)
	}
	defer cc.Close()

	client := guestv1.NewGuestPodPlaneClient(cc)
	stream, err := client.Attach(ctx)
	if err != nil {
		return fmt.Errorf("Attach: %w", err)
	}

	// Send the mandatory Hello first.
	if err := stream.Send(&guestv1.GuestFrame{
		Body: &guestv1.GuestFrame_Hello{
			Hello: &guestv1.GuestHello{
				PodId:       cfg.PodID,
				InitVersion: cfg.InitVersion,
				Kernel:      cfg.KernelInfo,
			},
		},
	}); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	// Receive HelloAck. We don't act on the PodSpec yet — the
	// per-container reconciliation lives in pkg/containers — but
	// logging it confirms the handshake completed.
	ack, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("recv hello-ack: %w", err)
	}
	switch b := ack.Body.(type) {
	case *guestv1.GuestFrame_HelloAck:
		spec := b.HelloAck.GetSpec()
		var containers int
		if spec != nil {
			containers = len(spec.GetContainers())
		}
		cfg.Logger.Printf("guestplane: hello-ack received : pod=%s containers=%d", cfg.PodID, containers)
	default:
		return fmt.Errorf("expected GuestHelloAck, got %T", ack.Body)
	}

	bootTime := time.Now()

	// Heartbeat goroutine. errCh surfaces a send failure so the
	// main recv loop tears down on the SAME error rather than
	// silently looping with a dead stream.
	errCh := make(chan error, 2)
	heartbeatCtx, cancelHeartbeat := context.WithCancel(ctx)
	defer cancelHeartbeat()
	if cfg.HeartbeatTick > 0 {
		go func() {
			tick := time.NewTicker(cfg.HeartbeatTick)
			defer tick.Stop()
			for {
				select {
				case <-heartbeatCtx.Done():
					return
				case <-tick.C:
					uptime := uint64(time.Since(bootTime) / time.Millisecond)
					if err := stream.Send(&guestv1.GuestFrame{
						Body: &guestv1.GuestFrame_PodStatus{
							PodStatus: &guestv1.PodStatus{
								PodId:    cfg.PodID,
								UptimeMs: uptime,
							},
						},
					}); err != nil {
						errCh <- fmt.Errorf("send pod-status: %w", err)
						return
					}
				}
			}
		}()
	}

	// Recv loop : ControlRequest frames from the host go through
	// dispatchControl ; everything else we log + ignore.
	go func() {
		for {
			frame, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					errCh <- nil // clean close
					return
				}
				errCh <- fmt.Errorf("recv: %w", err)
				return
			}
			if cr := frame.GetControlReq(); cr != nil {
				resp := dispatchControl(ctx, cr, cfg.Dispatcher, cfg.Logger)
				if err := stream.Send(&guestv1.GuestFrame{
					Body: &guestv1.GuestFrame_ControlResp{ControlResp: resp},
				}); err != nil {
					errCh <- fmt.Errorf("send control-resp: %w", err)
					return
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
		_ = stream.CloseSend()
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// dispatchControl ACKs every incoming ControlRequest with a
// matching CallId, routing the action through dp when set. nil dp
// preserves the legacy "not yet routed to in-guest reconciler" Error
// — the host's correlator still gets a response on the wire, so the
// stream never stalls.
//
// Per-variant routing :
//
//	StopPod  → dp.StopPod(ctx, graceSeconds)
//	Kill     → dp.Kill(ctx, containerID, signal)  (signal defaults to "SIGTERM")
//	Exec     → dp.Exec(ctx, *guestv1.ExecInContainer)
//	Update   → dp.Update(ctx, *guestv1.UpdateContainer)
//
// A nil callback in dp falls back to the same "not wired" Error as a
// nil dp — so the agent can opt into a subset of variants without a
// custom dispatch shape.
func dispatchControl(ctx context.Context, cr *guestv1.ControlRequest, dp *Dispatcher, logger *log.Logger) *guestv1.ControlResponse {
	logger.Printf("guestplane: control req call_id=%d op=%T", cr.GetCallId(), cr.GetOp())
	resp := &guestv1.ControlResponse{CallId: cr.GetCallId()}
	const unwired = "guestplane: control dispatch not yet routed to in-guest reconciler"

	if dp == nil {
		resp.Error = unwired
		return resp
	}

	var err error
	switch op := cr.GetOp().(type) {
	case *guestv1.ControlRequest_StopPod:
		if dp.StopPod == nil {
			resp.Error = unwired
			return resp
		}
		err = dp.StopPod(ctx, op.StopPod.GetGraceSeconds())
	case *guestv1.ControlRequest_Kill:
		if dp.Kill == nil {
			resp.Error = unwired
			return resp
		}
		sig := op.Kill.GetSignal()
		if sig == "" {
			sig = "SIGTERM"
		}
		err = dp.Kill(ctx, op.Kill.GetContainerId(), sig)
	case *guestv1.ControlRequest_Exec:
		if dp.Exec == nil {
			resp.Error = unwired
			return resp
		}
		err = dp.Exec(ctx, op.Exec)
	case *guestv1.ControlRequest_Update:
		if dp.Update == nil {
			resp.Error = unwired
			return resp
		}
		err = dp.Update(ctx, op.Update)
	default:
		// Empty op or an unknown variant — ack with an Error so the
		// host's dispatcher surfaces the gap rather than blocking.
		resp.Error = fmt.Sprintf("guestplane: unknown ControlRequest op %T", op)
		return resp
	}

	if err != nil {
		resp.Error = err.Error()
	}
	return resp
}
