//go:build !linux

package containers

// runtime_stub.go — the non-Linux fallback Runtime. Used in tests
// + when loom-server (which transitively imports this package via
// the dev workspace provisioner) is built on macOS / Windows.
//
// Tracks the in-memory state only ; no actual containers spawned.
// Useful as the dev-mode workspace where "containers" are simulated
// as the host's existing PATH (texlive on the macOS host = the same
// pdflatex the dev would have invoked anyway).

import (
	"context"
	"sync"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// StubRuntime tracks pulled images + running container names without
// touching any real runtime. Concurrent-safe.
type StubRuntime struct {
	mu      sync.Mutex
	Pulled  map[string]struct{}
	Started map[string]pod.WorkloadContainer
}

func NewStubRuntime() *StubRuntime {
	return &StubRuntime{
		Pulled:  map[string]struct{}{},
		Started: map[string]pod.WorkloadContainer{},
	}
}

func (r *StubRuntime) Pull(_ context.Context, image string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Pulled[image] = struct{}{}
	return nil
}

func (r *StubRuntime) Start(_ context.Context, c pod.WorkloadContainer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Started[c.Name] = c
	return nil
}

func (r *StubRuntime) Stop(_ context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.Started, name)
	return nil
}

func (r *StubRuntime) Running(_ context.Context) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.Started))
	for k := range r.Started {
		out = append(out, k)
	}
	return out, nil
}
