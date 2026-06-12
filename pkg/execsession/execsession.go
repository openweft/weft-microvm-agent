// Package execsession is the VM side of the user shell — and of every
// `crun exec` invocation. loom-server opens a session by publishing
// on `weft.exec.<vmID>.<sid>.open` (a JSON ExecRequest), then frames
// flow over two ephemeral subjects :
//
//   weft.exec.<vmID>.<sid>.in   — frames TO the pty
//                                  'i' + payload     stdin
//                                  'r' + cols(u16) + rows(u16) resize
//                                  'x'               eof / close
//
//   weft.exec.<vmID>.<sid>.out  — frames FROM the pty
//                                  'o' + payload     stdout
//                                  'e' + code(u32)  exited (process exit)
//
// The same 1-byte-prefix wire shape as loom-server's existing
// /api/projects/{p}/shell — so the SPA bridge can forward bytes
// verbatim, the loom-server is a dumb proxy, and replacing local pty
// with NATS exec is a router change rather than a protocol change.
//
// Two target modes :
//
//   Target.Kind = "shell"   — spawn /bin/bash inside the VM root.
//                              The default shell-tab session.
//   Target.Kind = "exec"    — `crun exec <container>` with given
//                              Command/Args. Used for compile jobs
//                              + tool wrappers (`pdflatex` etc.)
//
// Eviction : a session is closed when the input stream sends 'x',
// the underlying process exits, or the open-publisher disconnects
// (via JetStream subscription drop). Sessions never persist across
// agent restarts — the SPA reconnects + opens a fresh one.
package execsession

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// SubjectOpen is the request subject for opening a new session.
func SubjectOpen(vmID string) string { return "weft.exec." + vmID + ".open" }

// SubjectIn / SubjectOut are the per-session frame subjects.
func SubjectIn(vmID, sid string) string  { return "weft.exec." + vmID + "." + sid + ".in" }
func SubjectOut(vmID, sid string) string { return "weft.exec." + vmID + "." + sid + ".out" }

// ExecRequest is what loom-server publishes on SubjectOpen. ID is
// chosen by the publisher (typically a ULID), so the SPA can
// preconfigure its in/out subscriptions before the agent acks open.
type ExecRequest struct {
	ID     string     `json:"id"`
	Target ExecTarget `json:"target"`
	// InitialSize lets the agent allocate the pty at the right
	// dimensions before any 'r' frame arrives. Optional.
	InitialCols uint16 `json:"cols,omitempty"`
	InitialRows uint16 `json:"rows,omitempty"`
}

// ExecTarget tells the agent which process to spawn. Shell vs exec
// is the only structural split.
type ExecTarget struct {
	Kind string `json:"kind"` // "shell" | "exec"
	// For Kind="shell" : Command/Args/Env optionally override
	// /bin/bash. Empty = sensible defaults.
	// For Kind="exec"  : Container must be set ; Command + Args are
	// passed to `crun exec`.
	Container string            `json:"container,omitempty"`
	Command   []string          `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	WorkDir   string            `json:"work_dir,omitempty"`
}

// Validate is the schema check the agent runs before opening a
// session. Returns the descriptive error a loom-doctor surface can
// surface back to the publisher.
func (r *ExecRequest) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("exec: ID required")
	}
	switch r.Target.Kind {
	case "shell":
		// OK — defaults to bash
	case "exec":
		if r.Target.Container == "" {
			return fmt.Errorf("exec: container required when kind=exec")
		}
		if len(r.Target.Command) == 0 {
			return fmt.Errorf("exec: command required when kind=exec")
		}
	default:
		return fmt.Errorf("exec: invalid kind %q (shell|exec)", r.Target.Kind)
	}
	return nil
}

// Sessions tracks every live execution so the agent can clean up
// (kill pty, unsubscribe from in subject) when an open-publisher
// drops or the process exits. Concurrent-safe.
type Sessions struct {
	mu   sync.Mutex
	live map[string]*session
}

type session struct {
	id     string
	cancel context.CancelFunc
}

// NewSessions builds an empty session registry. Agent main wires
// the NATS subscriber that calls Open / Close from message handlers.
func NewSessions() *Sessions {
	return &Sessions{live: map[string]*session{}}
}

// Open registers a new session under id ; cancel will be invoked
// when Close(id) is called or the registry is shutdown.
func (s *Sessions) Open(id string, cancel context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.live[id]; ok {
		// Replace : the publisher reissued open with the same ID,
		// stale session needs to die first.
		existing.cancel()
	}
	s.live[id] = &session{id: id, cancel: cancel}
}

// Close stops the session with id (no-op if unknown).
func (s *Sessions) Close(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.live[id]; ok {
		existing.cancel()
		delete(s.live, id)
	}
}

// CloseAll terminates every live session — called on agent shutdown.
func (s *Sessions) CloseAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sn := range s.live {
		sn.cancel()
	}
	s.live = map[string]*session{}
}

// DecodeRequest unmarshals an ExecRequest + validates it. Same
// testable shape as the other agent reconcilers.
func DecodeRequest(data []byte) (ExecRequest, error) {
	var r ExecRequest
	if err := json.Unmarshal(data, &r); err != nil {
		return r, fmt.Errorf("decode exec request: %w", err)
	}
	if err := r.Validate(); err != nil {
		return r, err
	}
	return r, nil
}
