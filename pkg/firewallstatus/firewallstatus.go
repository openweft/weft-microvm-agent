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

// Emitter periodically reads + publishes FirewallStatus for one VM.
type Emitter struct {
	nc       *nats.Conn
	vmID     string
	read     ReadFunc
	interval time.Duration
	now      func() time.Time // injectable for tests
	logger   *log.Logger
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

// publishOnce reads, stamps, encodes, publishes. Errors are
// swallowed after logging — we never let a transient hiccup stop
// the ticker.
func (e *Emitter) publishOnce() {
	status := e.read()
	status.PublishedAtUnix = e.now().Unix()
	data, err := json.Marshal(status)
	if err != nil {
		e.logger.Printf("firewallstatus: marshal: %v", err)
		return
	}
	if err := e.nc.Publish(Subject(e.vmID), data); err != nil {
		e.logger.Printf("firewallstatus: publish: %v", err)
		return
	}
}
