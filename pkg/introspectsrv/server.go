// Package introspectsrv implements the weft.introspect.v1.Introspect
// gRPC service: a read-only window into the micro-VM, served on the
// VM's wg0 address for an operator CLI to reach over WireGuard.
package introspectsrv

import (
	"context"

	"github.com/openweft/weft-microvm-agent/pkg/procps"
	introspectv1 "github.com/openweft/weft-proto/introspectv1"
)

// Server implements introspectv1.IntrospectServer.
type Server struct {
	introspectv1.UnimplementedIntrospectServer

	// list returns the process table; defaults to procps.List, overridable
	// in tests.
	list func() ([]procps.Process, error)
}

// New returns a Server backed by the live /proc filesystem.
func New() *Server {
	return &Server{list: procps.List}
}

// ListProcesses returns the VM's process table — the gRPC `ps aux`.
func (s *Server) ListProcesses(_ context.Context, _ *introspectv1.ListProcessesRequest) (*introspectv1.ListProcessesResponse, error) {
	procs, err := s.list()
	if err != nil {
		return nil, err
	}
	out := &introspectv1.ListProcessesResponse{
		Processes: make([]*introspectv1.Process, 0, len(procs)),
	}
	for _, p := range procs {
		out.Processes = append(out.Processes, &introspectv1.Process{
			Pid:         p.PID,
			Ppid:        p.PPID,
			User:        p.User,
			State:       p.State,
			CpuPercent:  p.CPUPercent,
			MemPercent:  p.MemPercent,
			VszKb:       p.VSZKB,
			RssKb:       p.RSSKB,
			Tty:         p.TTY,
			StartTimeMs: p.StartTimeMS,
			Command:     p.Command,
		})
	}
	return out, nil
}
