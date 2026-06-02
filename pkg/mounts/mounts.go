// Package mounts is the VM side of dynamic share mounts. An operator
// (e.g. a teacher) publishes a ShareMount on the event bus — to one VM, or
// via control-plane fan-out to a whole class of student VMs — and each VM
// applies it: mount on action "" / "mount", tear down on "unmount".
//
// State is pushed whole and applied idempotently (replace-by-ID), so a
// missed message self-heals on the next publish — the same model pkg/mesh
// uses for WireGuard membership.
package mounts

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/nats-io/nats.go"
	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// Subject is the per-VM event-bus subject share mount updates arrive on.
// A class-wide publish is the control plane's job: it resolves the group
// to its VMs and publishes to each VM's subject (mirrors how weft fans out
// mesh updates), so the guest only ever trusts its own subject.
func Subject(vmID string) string { return "weft.mounts." + vmID }

// ApplyFunc mounts or unmounts one share according to spec.Action. The real
// implementation drives the CubeFS FUSE client (Linux); tests inject a stub.
type ApplyFunc func(pod.ShareMount) error

// HandleMessage decodes a published mount update and applies it. Pure
// aside from the injected apply, so the decode/validate path is testable
// without a broker or a kernel.
func HandleMessage(data []byte, apply ApplyFunc) error {
	var m pod.ShareMount
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("decode mount update: %w", err)
	}
	if err := m.Validate(); err != nil {
		return fmt.Errorf("invalid mount update: %w", err)
	}
	return apply(m)
}

// Subscriber listens for this VM's share-mount updates and applies each one.
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

// Start subscribes to the VM's mounts subject. The returned subscription
// is live until unsubscribed or the connection drops.
func (s *Subscriber) Start() (*nats.Subscription, error) {
	return s.nc.Subscribe(Subject(s.vmID), func(m *nats.Msg) {
		var last pod.ShareMount
		// Capture the validated spec via a wrapping apply so the log line
		// can mention what was applied without re-decoding the payload and
		// without changing the HandleMessage contract shared by all
		// per-concern Subscribers in this agent.
		err := HandleMessage(m.Data, func(spec pod.ShareMount) error {
			last = spec
			return s.apply(spec)
		})
		if err != nil {
			s.logger.Printf("mounts: %v", err)
			return
		}
		action := last.Action
		if action == "" {
			action = pod.MountAction("mount")
		}
		s.logger.Printf("mounts: applied %s id=%s mount=%s", action, last.ID, last.MountPoint)
	})
}
