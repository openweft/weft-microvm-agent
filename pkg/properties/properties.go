// Package properties is the guest-side application of dynamically-
// pushed VM properties. The host (weft-agent) publishes the full set
// of guest-readable properties for this VM on every change ; the
// subscriber mirrors them to a local POSIX tree so any in-VM process
// can `cat /run/weft/properties/<key>` without speaking a custom API.
//
// Only the guest_readable=true properties reach this surface — the
// host filters before publishing (host-only metadata like cost-center
// or security labels never crosses the boundary).
//
// Same Subscriber+ApplyFunc pattern as [[sshkeys]] / [[mesh]] /
// [[mounts]] : state pushed whole, missed messages self-heal on next
// publish. An empty set means "no properties" and IS applied — the
// guest tree is cleared.
//
// Key conventions :
//   - Free-form, but the segment separator is "/" (k8s/Docker style).
//   - The "weft.boot/*" prefix is reserved for first-boot provisioning
//     (set by CreateVM, consumed by the boot concern). Operators may
//     read but should not hand-edit.
//   - "/" in the property key maps to filesystem nesting on apply.
//     "owner" → <root>/owner ; "weft.boot/script" → <root>/weft.boot/script.
package properties

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/nats-io/nats.go"
)

// Subject is the per-VM NATS subject the host publishes properties on.
func Subject(vmID string) string { return "weft.properties." + vmID }

// PropertySet is the desired set of properties at this point in time.
// Keys are property names ; values are the (possibly multi-line)
// content. An empty map means "no properties" and triggers a clear.
type PropertySet struct {
	Properties map[string]string `json:"properties"`
}

// Validate rejects keys that would escape the property tree on
// apply : empty, absolute paths, or paths containing "..". The host
// is supposed to filter these already ; this is the guest's defence
// in depth.
func (s PropertySet) Validate() error {
	for k := range s.Properties {
		if k == "" {
			return fmt.Errorf("empty property key")
		}
		if strings.HasPrefix(k, "/") {
			return fmt.Errorf("property key %q starts with '/'", k)
		}
		if strings.Contains(k, "..") {
			return fmt.Errorf("property key %q contains '..'", k)
		}
		// Guard against NUL or other unprintables that the host
		// shouldn't be emitting but might.
		if strings.ContainsRune(k, 0) {
			return fmt.Errorf("property key contains NUL")
		}
	}
	return nil
}

// ApplyFunc applies the desired set to the guest. The real impl
// syncs /run/weft/properties/ ; tests inject a stub.
type ApplyFunc func(PropertySet) error

// HandleMessage decodes a published update and applies it. Pure
// aside from the injected apply.
func HandleMessage(data []byte, apply ApplyFunc) error {
	var ps PropertySet
	if err := json.Unmarshal(data, &ps); err != nil {
		return fmt.Errorf("decode properties update: %w", err)
	}
	if err := ps.Validate(); err != nil {
		return fmt.Errorf("invalid properties update: %w", err)
	}
	return apply(ps)
}

// Subscriber listens for this VM's property updates and applies each.
type Subscriber struct {
	nc     *nats.Conn
	vmID   string
	apply  ApplyFunc
	logger *log.Logger
}

// NewSubscriber builds a Subscriber for vmID.
func NewSubscriber(nc *nats.Conn, vmID string, apply ApplyFunc, logger *log.Logger) *Subscriber {
	if logger == nil {
		logger = log.Default()
	}
	return &Subscriber{nc: nc, vmID: vmID, apply: apply, logger: logger}
}

// Start subscribes to the VM's properties subject. Returned
// subscription stays live until unsubscribed or the connection drops.
func (s *Subscriber) Start() (*nats.Subscription, error) {
	return s.nc.Subscribe(Subject(s.vmID), func(m *nats.Msg) {
		if err := HandleMessage(m.Data, s.apply); err != nil {
			s.logger.Printf("properties: %v", err)
			return
		}
		var ps PropertySet
		_ = json.Unmarshal(m.Data, &ps)
		s.logger.Printf("properties: applied update for %s (%d keys)", s.vmID, len(ps.Properties))
	})
}
