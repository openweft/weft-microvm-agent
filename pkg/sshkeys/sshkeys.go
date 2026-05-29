// Package sshkeys is the guest-side application of dynamically-pushed
// SSH authorized-keys updates. The host (weft-agent, or — until that
// lands — weft-webui's in-memory store) publishes the full desired
// set of keys for this VM whenever the catalogue changes ; the
// subscriber re-writes the target user's authorized_keys atomically
// (idempotent, replace-set).
//
// Same Subscriber+ApplyFunc pattern as [[mesh]] and [[mounts]] :
// state is pushed whole rather than diffed, so a missed message
// self-heals on the next publish.
//
// The actual file write is injected by the caller (ApplyFunc) so the
// pure decode/validate path is testable without root or a real
// filesystem.
package sshkeys

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/nats-io/nats.go"
)

// Subject is the per-VM NATS subject the host publishes SSH-keys
// updates on.
func Subject(vmID string) string { return "weft.sshkeys." + vmID }

// Key is one authorized-key entry. `PublicKey` is the full OpenSSH
// line (`<type> <base64> [comment]`) ; the fingerprint is host-side
// bookkeeping and isn't needed inside the guest.
type Key struct {
	PublicKey string `json:"public_key"`
}

// KeySet is the desired set of keys for this VM at this point in
// time. Empty Keys is a legitimate state — "no key authorised" — and
// MUST be applied (writing an empty authorized_keys, not skipping).
type KeySet struct {
	Keys []Key `json:"keys"`
}

// Validate enforces the minimal shape every key line needs : a type
// prefix (one of the known OpenSSH algorithms) followed by a base64
// blob. Comments are optional. We don't decode the base64 or compute
// the fingerprint here — the host did that already, and a guest that
// re-validated would just be double-checking the wire.
func (s KeySet) Validate() error {
	for i, k := range s.Keys {
		parts := strings.Fields(k.PublicKey)
		if len(parts) < 2 {
			return fmt.Errorf("key %d: expected '<type> <base64> [comment]', got %q", i, k.PublicKey)
		}
		switch parts[0] {
		case "ssh-rsa", "ssh-ed25519", "ssh-dss",
			"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
			// fine
		default:
			return fmt.Errorf("key %d: unsupported algorithm %q", i, parts[0])
		}
	}
	return nil
}

// ApplyFunc applies the desired key set to the guest. The real
// implementation rewrites the target user's authorized_keys
// atomically (see cmd/weft-vm-agent/sshkeys_linux.go). Tests inject
// a stub.
type ApplyFunc func(KeySet) error

// HandleMessage decodes a published update and applies it. Pure aside
// from the injected apply — the decode/validate path runs without a
// filesystem or a broker.
func HandleMessage(data []byte, apply ApplyFunc) error {
	var ks KeySet
	if err := json.Unmarshal(data, &ks); err != nil {
		return fmt.Errorf("decode sshkeys update: %w", err)
	}
	if err := ks.Validate(); err != nil {
		return fmt.Errorf("invalid sshkeys update: %w", err)
	}
	return apply(ks)
}

// Subscriber listens for this VM's sshkeys updates and applies each.
type Subscriber struct {
	nc     *nats.Conn
	vmID   string
	apply  ApplyFunc
	logger *log.Logger
}

// NewSubscriber builds a Subscriber for vmID that applies updates
// via apply.
func NewSubscriber(nc *nats.Conn, vmID string, apply ApplyFunc, logger *log.Logger) *Subscriber {
	if logger == nil {
		logger = log.Default()
	}
	return &Subscriber{nc: nc, vmID: vmID, apply: apply, logger: logger}
}

// Start subscribes to the VM's sshkeys subject. The returned
// subscription is live until unsubscribed or the connection drops.
func (s *Subscriber) Start() (*nats.Subscription, error) {
	return s.nc.Subscribe(Subject(s.vmID), func(m *nats.Msg) {
		if err := HandleMessage(m.Data, s.apply); err != nil {
			s.logger.Printf("sshkeys: %v", err)
			return
		}
		s.logger.Printf("sshkeys: applied update for %s (%d keys)", s.vmID, lenAfterDecode(m.Data))
	})
}

// lenAfterDecode peeks at the size hint for the log line. Cheap on
// the hot path ; failure just means we log "?" instead.
func lenAfterDecode(data []byte) int {
	var ks KeySet
	if err := json.Unmarshal(data, &ks); err != nil {
		return -1
	}
	return len(ks.Keys)
}
