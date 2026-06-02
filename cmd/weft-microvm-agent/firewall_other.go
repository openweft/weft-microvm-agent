//go:build !linux

package main

import (
	"fmt"

	agentfirewall "github.com/openweft/weft-microvm-agent/pkg/firewall"
	agentfirewallstatus "github.com/openweft/weft-microvm-agent/pkg/firewallstatus"
	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// firewallApply is unavailable off Linux — the agent only programmes
// nftables inside a Linux micro-VM. Stub present so the command still
// builds for host-side dev (matches the meshApply / sshkeysApply split).
var firewallApply agentfirewall.ApplyFunc = func(*pod.Firewall) error {
	return fmt.Errorf("firewall apply requires linux (nftables)")
}

// firewallStatusRead off Linux returns a "no kernel" stub so the
// emitter ticker still runs (useful for host-side dev). The wire
// payload is well-formed JSON — the UI can render the Degraded
// state without special casing.
var firewallStatusRead agentfirewallstatus.ReadFunc = func() pod.FirewallStatus {
	return pod.FirewallStatus{Overall: "Degraded", LastError: "nftables read requires linux"}
}
