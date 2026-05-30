// Package mesh is the VM side of dynamic WireGuard mesh updates. weft
// publishes a VM's full desired wg0 config on the event bus whenever the
// mesh membership changes; the VM subscribes and re-applies it (replace-set,
// idempotent). State is pushed whole rather than diffed, so a missed message
// self-heals on the next publish.
package mesh

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/nats-io/nats.go"
	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// Subject is the per-VM event-bus subject weft publishes mesh updates on.
func Subject(vmID string) string { return "weft.mesh." + vmID }

// ApplyFunc applies a desired WireGuard config to the kernel. The real
// implementation is network.ApplyWireGuard (Linux); tests inject a stub.
type ApplyFunc func(*pod.WireGuard) error

// HandleMessage decodes a published mesh update and applies it. Pure aside
// from the injected apply, so the decode/validate path is testable without a
// kernel or a broker.
func HandleMessage(data []byte, apply ApplyFunc) error {
	var wg pod.WireGuard
	if err := json.Unmarshal(data, &wg); err != nil {
		return fmt.Errorf("decode mesh update: %w", err)
	}
	if err := wg.Validate(); err != nil {
		return fmt.Errorf("invalid mesh update: %w", err)
	}
	return apply(&wg)
}

// Subscriber listens for this VM's mesh updates and applies each one.
type Subscriber struct {
	nc     *nats.Conn
	vmID   string
	apply  ApplyFunc
	logger *log.Logger
}

// NewSubscriber builds a Subscriber for vmID that applies updates via apply.
func NewSubscriber(nc *nats.Conn, vmID string, apply ApplyFunc, logger *log.Logger) *Subscriber {
	if logger == nil {
		logger = log.Default()
	}
	return &Subscriber{nc: nc, vmID: vmID, apply: apply, logger: logger}
}

// Start subscribes to the VM's mesh subject. The returned subscription is
// live until unsubscribed or the connection drops.
func (s *Subscriber) Start() (*nats.Subscription, error) {
	return s.nc.Subscribe(Subject(s.vmID), func(m *nats.Msg) {
		if err := HandleMessage(m.Data, s.apply); err != nil {
			s.logger.Printf("mesh: %v", err)
			return
		}
		s.logger.Printf("mesh: applied update for %s", s.vmID)
	})
}
