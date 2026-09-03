//go:build linux

package main

import (
	agentmesh "github.com/openweft/weft-microvm-agent/pkg/mesh"
	netmesh "github.com/openweft/weft-microvm-init/pkg/network"
)

// meshApply is the real kernel applier on Linux: a published mesh update is
// the VM's full desired wg0 config, applied via netlink (replace-set).
var meshApply agentmesh.ApplyFunc = netmesh.ApplyWireGuard
