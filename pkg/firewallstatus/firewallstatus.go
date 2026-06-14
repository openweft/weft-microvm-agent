// Package firewallstatus publishes this micro-VM's live nftables
// state on the per-VM NATS subject the control plane (and the UI)
// listen on.
//
// Reverse direction of pkg/firewall : where the firewall subscriber
// pulls a desired ruleset on weft.firewall.<vm-uuid> and reconciles
// the kernel table, this emitter polls the kernel table and pushes
// a [[pod.FirewallStatus]] on weft.firewall.<vm-uuid>.status. Same
// shape weft-router's statusemitter uses for its BGP RouterStatus.
//
// Cadence : a ticker (default 10 s) calls the ReadFunc, stamps the
// status with the current wall-clock time, and publishes. The first
// tick fires immediately at Run() entry so a dashboard sees a value
// inside a second of boot. Best-effort : publish or read failures
// log + skip ; the next tick reconciles.
package firewallstatus

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// Subject returns the per-VM NATS subject status messages publish to.
// Sibling of pkg/firewall.Subject : same VM id, ".status" suffix.
func Subject(vmID string) string { return "weft.firewall." + vmID + ".status" }

// ReadFunc returns the current FirewallStatus, typically by
// inspecting the kernel nftables table. Production implementation
// is network.ReadFirewallStatus ; tests inject a stub.
type ReadFunc func() pod.FirewallStatus

// PublishHook is the metrics seam : Emitter calls it exactly once per
// publishOnce invocation, after the publish attempt returns, with the
// transport error (nil on success). cmd-side wiring routes it to the
// agent's metrics.Recorder so a parallel counter to apply_total ticks
// on every status emission ; tests leave it nil.
//
// Kept narrow on purpose : the hook receives only the error, not the
// payload, so a future call-site can wire a different observer (logs,
// audit, derived gauges) without ratcheting up the contract.
type PublishHook func(err error)

// Emitter periodically reads + publishes FirewallStatus for one VM.
type Emitter struct {
	nc       *nats.Conn
	vmID     string
	read     ReadFunc
	interval time.Duration
	now      func() time.Time // injectable for tests
	logger   *log.Logger
	hook     PublishHook
}

// New constructs an Emitter. interval <= 0 defaults to 10 s.
// logger nil defaults to log.Default.
func New(nc *nats.Conn, vmID string, read ReadFunc, interval time.Duration, logger *log.Logger) (*Emitter, error) {
	if nc == nil {
		return nil, fmt.Errorf("firewallstatus.New: nil nats conn")
	}
	if vmID == "" {
		return nil, fmt.Errorf("firewallstatus.New: empty vmID")
	}
	if read == nil {
		return nil, fmt.Errorf("firewallstatus.New: nil read func")
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Emitter{
		nc: nc, vmID: vmID, read: read, interval: interval,
		now: time.Now, logger: logger,
	}, nil
}

// Run ticks every interval until ctx is cancelled. Publishes one
// status message immediately on entry so a fresh boot is visible
// without waiting for the first tick.
func (e *Emitter) Run(ctx context.Context) error {
	e.publishOnce()
	t := time.NewTicker(e.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			e.publishOnce()
		}
	}
}

// SetMetricsHook installs a PublishHook the Emitter calls after every
// publishOnce. Safe to call before Run() ; calling after Run starts
// is allowed but races with the first tick — wire the hook at
// construction time in cmd/weft-microvm-agent for deterministic
// counts. Passing nil clears the hook.
//
// Exported strictly as the metrics surface ; sibling subscribers
// (mesh / mounts / firewall) wire metrics at the ApplyFunc seam
// instead, but the Emitter owns its own publish loop so the hook
// belongs to the type.
func (e *Emitter) SetMetricsHook(h PublishHook) {
	e.hook = h
}

// publishOnce reads, stamps, encodes, publishes. Errors are
// swallowed after logging — we never let a transient hiccup stop
// the ticker.
//
// The metrics hook fires on EVERY return path : marshal failures
// (rare — pod.FirewallStatus is a fixed shape, but the API is
// future-proofed), publish failures, and the happy path. The hook
// receives the most recently observed error so the counter's
// result label reflects the actual outcome.
func (e *Emitter) publishOnce() {
	var publishErr error
	defer func() {
		if e.hook != nil {
			e.hook(publishErr)
		}
	}()
	status := e.read()
	status.PublishedAtUnix = e.now().Unix()
	data, err := json.Marshal(status)
	if err != nil {
		publishErr = err
		e.logger.Printf("firewallstatus: marshal: %v", err)
		return
	}
	if err := e.nc.Publish(Subject(e.vmID), data); err != nil {
		publishErr = err
		e.logger.Printf("firewallstatus: publish: %v", err)
		return
	}
}
