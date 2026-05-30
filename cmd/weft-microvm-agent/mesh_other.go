//go:build !linux

package main

import (
	"fmt"

	"github.com/openweft/weft-microvm-init/pkg/pod"
	agentmesh "github.com/openweft/weft-microvm-agent/pkg/mesh"
)

// meshApply is unavailable off Linux — the agent only configures wg0 inside a
// Linux micro-VM. Present so the command still builds for host-side dev.
var meshApply agentmesh.ApplyFunc = func(*pod.WireGuard) error {
	return fmt.Errorf("mesh apply requires linux (kernel WireGuard)")
}
