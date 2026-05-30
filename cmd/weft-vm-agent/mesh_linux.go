//go:build linux

package main

import (
	netmesh "github.com/openweft/weft-microvm-init/pkg/network"
	agentmesh "github.com/openweft/weft-vm-agent/pkg/mesh"
)

// meshApply is the real kernel applier on Linux: a published mesh update is
// the VM's full desired wg0 config, applied via netlink (replace-set).
var meshApply agentmesh.ApplyFunc = netmesh.ApplyWireGuard
