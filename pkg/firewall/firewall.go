// Package firewall is the VM side of dynamic stateful packet filtering.
//
// weft (control plane) publishes the per-VM effective ruleset — a flat
// [[pod.Firewall]] derived from every Security-Group the VM belongs to,
// with remote_group_uuid references already expanded into concrete
// CIDRs — on the per-VM event-bus subject. The agent reconciles its
// nftables table whole on every push : replace-set, idempotent, a
// missed message self-heals on the next publish.
//
// Pattern matches pkg/mesh and pkg/mounts: one Subscriber, one
// ApplyFunc, JSON payload of a single [[pod.Firewall]]. The actual
// nftables reconciler lives next to the binary (firewall_linux.go),
// not here, so this package stays pure-Go and testable on darwin.
package firewall

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/nats-io/nats.go"
	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// Subject is the per-VM event-bus subject firewall ruleset updates
// arrive on. Aligned with mesh/mounts naming so wildcard auth policies
// in NATS stay consistent (weft.<concern>.<vm-uuid>).
func Subject(vmID string) string { return "weft.firewall." + vmID }

// ApplyFunc reconciles the kernel firewall to the desired ruleset.
// The real implementation drives nftables via netlink (Linux); tests
// inject a stub.
type ApplyFunc func(*pod.Firewall) error

// HandleMessage decodes a published firewall update and applies it.
// Pure aside from the injected apply, so the decode/validate path is
// testable without nftables or a NATS server.
func HandleMessage(data []byte, apply ApplyFunc) error {
	var fw pod.Firewall
	if err := json.Unmarshal(data, &fw); err != nil {
		return fmt.Errorf("decode firewall update: %w", err)
	}
	if err := fw.Validate(); err != nil {
		return fmt.Errorf("invalid firewall update: %w", err)
	}
	return apply(&fw)
}

// Subscriber listens for this VM's firewall updates and applies each one.
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

// Start subscribes to the VM's firewall subject. The returned
// subscription is live until unsubscribed or the connection drops.
func (s *Subscriber) Start() (*nats.Subscription, error) {
	return s.nc.Subscribe(Subject(s.vmID), func(m *nats.Msg) {
		var rules int
		err := HandleMessage(m.Data, func(fw *pod.Firewall) error {
			rules = len(fw.Rules)
			return s.apply(fw)
		})
		if err != nil {
			s.logger.Printf("firewall: %v", err)
			return
		}
		s.logger.Printf("firewall: applied %d rule(s) for %s", rules, s.vmID)
	})
}
