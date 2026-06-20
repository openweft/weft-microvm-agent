//go:build !linux

package network

import "github.com/openweft/weft-microvm-init/pkg/pod"

// ReadFirewallStatus on non-Linux returns a stub "no kernel here"
// status so the emitter goroutine still ticks (useful for host-
// side dev where the agent binary is built but never sees an
// nftables-aware kernel). PublishedAtUnix left zero — the emitter
// stamps it.
func ReadFirewallStatus() pod.FirewallStatus {
	return pod.FirewallStatus{
		Overall:   "Degraded",
		LastError: "nftables read requires linux",
	}
}
