//go:build linux

package execsession

// subscriber_linux.go — wire the pty pump to NATS. Subscribe to
// `weft.exec.<vmID>.open`, validate every incoming ExecRequest,
// then launch Run in a goroutine. Tracks live sessions so an
// agent shutdown tears them down deterministically.

import (
	"context"
	"fmt"

	"github.com/nats-io/nats.go"
)

// Subscriber owns the open subscription + the live sessions registry.
// Pattern mirrors pkg/mounts.Subscriber so the agent's main can wire
// it uniformly with the other reconcilers.
type Subscriber struct {
	nc       *nats.Conn
	vmID     string
	sessions *Sessions
	sub      *nats.Subscription
	logger   Logger
}

// Logger is the slice of *log.Logger this package wants — mirrors
// pkg/mounts.Logger so we avoid a hard log/slog dep in the agent.
type Logger interface {
	Printf(format string, args ...any)
}

// NewSubscriber builds a Subscriber over nc bound to vmID. Logger
// may be nil ; we silently drop log lines in that case.
func NewSubscriber(nc *nats.Conn, vmID string, logger Logger) *Subscriber {
	return &Subscriber{
		nc:       nc,
		vmID:     vmID,
		sessions: NewSessions(),
		logger:   logger,
	}
}

// Start subscribes to the agent's open subject + dispatches each
// validated ExecRequest to Run on its own goroutine. The returned
// stop fn unsubscribes + cancels every live session.
func (s *Subscriber) Start(ctx context.Context) (stop func(), err error) {
	sub, err := s.nc.Subscribe(SubjectOpen(s.vmID), func(m *nats.Msg) {
		req, derr := DecodeRequest(m.Data)
		if derr != nil {
			s.log("execsession: bad open request: %v", derr)
			return
		}
		sessCtx, cancel := context.WithCancel(ctx)
		s.sessions.Open(req.ID, cancel)
		go func() {
			defer s.sessions.Close(req.ID)
			if runErr := Run(sessCtx, PumpConfig{
				NC:      s.nc,
				VMID:    s.vmID,
				Request: req,
			}); runErr != nil {
				s.log("execsession: pump error sid=%s: %v", req.ID, runErr)
			}
		}()
	})
	if err != nil {
		return nil, fmt.Errorf("execsession subscribe: %w", err)
	}
	s.sub = sub
	stop = func() {
		_ = sub.Unsubscribe()
		s.sessions.CloseAll()
	}
	return stop, nil
}

func (s *Subscriber) log(format string, args ...any) {
	if s.logger == nil {
		return
	}
	s.logger.Printf(format, args...)
}
