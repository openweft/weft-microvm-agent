//go:build !linux

package network

import (
	"fmt"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// ApplyFirewall is unavailable off Linux — the agent only filters
// packets inside a Linux micro-VM. The stub is present so the agent
// binary still builds on the host-side dev machine (darwin) for cross-
// platform tests.
func ApplyFirewall(*pod.Firewall) error {
	return fmt.Errorf("firewall apply requires linux (nftables)")
}
