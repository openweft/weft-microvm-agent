//go:build !linux

package main

import (
	"fmt"

	agentfirewall "github.com/openweft/weft-microvm-agent/pkg/firewall"
	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// firewallApply is unavailable off Linux — the agent only programmes
// nftables inside a Linux micro-VM. Stub present so the command still
// builds for host-side dev (matches the meshApply / sshkeysApply split).
var firewallApply agentfirewall.ApplyFunc = func(*pod.Firewall) error {
	return fmt.Errorf("firewall apply requires linux (nftables)")
}
