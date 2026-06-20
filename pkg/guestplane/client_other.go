//go:build !linux

// Non-Linux stub : the AF_VSOCK transport lives in
// weft-microvm-init's pkg/transport which is Linux-only (the
// kernel socket family doesn't exist elsewhere). The agent itself
// only runs in microVMs, so this stub is purely there to keep
// `go test ./...` green on darwin / macOS developer machines.

package guestplane

import (
	"context"
	"errors"
	"log"
	"time"
)

const DefaultPort uint32 = 7777

const (
	DefaultDialAttempts  = 60
	DefaultDialDelay     = 1 * time.Second
	DefaultHeartbeatTick = 10 * time.Second
	DefaultReconnectGap  = 5 * time.Second
)

type Config struct {
	HostCID       uint32
	Port          uint32
	PodID         string
	KernelInfo    string
	InitVersion   string
	HeartbeatTick time.Duration
	ReconnectGap  time.Duration
	DialAttempts  int
	DialDelay     time.Duration
	Logger        *log.Logger
}

// Run on non-Linux returns immediately with an error. The agent
// only ships into Linux microVMs ; this stub keeps the build green
// elsewhere so test runners + IDEs on darwin still compile the
// package.
func Run(_ context.Context, _ Config) error {
	return errors.New("guestplane: AF_VSOCK is Linux-only ; this build is a non-Linux stub")
}
