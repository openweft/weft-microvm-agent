//go:build !linux

package execsession

// subscriber_other.go — non-Linux stub. The agent's pty/exec
// subsystem hard-depends on Linux primitives (openpty, setns,
// crun exec) so on darwin/freebsd we ship a no-op Subscriber.
// Mirrors the firewall_other.go / mesh_other.go convention :
// the binary still builds for cross-compile workflows (CI
// matrix, local docker-on-mac validation), but startExecSession
// is effectively a passthrough on non-Linux hosts.

import (
	"context"

	"github.com/nats-io/nats.go"
)

type Subscriber struct {
	vmID   string
	logger Logger
}

type Logger interface {
	Printf(format string, args ...any)
}

func NewSubscriber(_ *nats.Conn, vmID string, logger Logger) *Subscriber {
	return &Subscriber{vmID: vmID, logger: logger}
}

func (s *Subscriber) Start(_ context.Context) (func(), error) {
	if s.logger != nil {
		s.logger.Printf("execsession: non-Linux build — subscriber inactive for vmID=%s", s.vmID)
	}
	return func() {}, nil
}
