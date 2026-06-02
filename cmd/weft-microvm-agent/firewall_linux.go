//go:build linux

package main

import (
	agentfirewall "github.com/openweft/weft-microvm-agent/pkg/firewall"
	agentfirewallstatus "github.com/openweft/weft-microvm-agent/pkg/firewallstatus"
	netfw "github.com/openweft/weft-microvm-init/pkg/network"
)

// firewallApply is the real kernel applier on Linux: a published
// firewall update is the VM's full desired ruleset, applied via
// netlink-based nftables (replace-table). Same shape as meshApply.
var firewallApply agentfirewall.ApplyFunc = netfw.ApplyFirewall

// firewallStatusRead is the real kernel reader on Linux: walks
// the nftables "weft-fw" table and returns a pod.FirewallStatus
// snapshot the emitter publishes.
var firewallStatusRead agentfirewallstatus.ReadFunc = netfw.ReadFirewallStatus
