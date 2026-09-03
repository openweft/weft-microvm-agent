// Package containers is the VM side of the dynamic container set.
// loom-server (or weft-agent reconciler) publishes a pod.ContainerSet
// on the per-VM subject `weft.containers.<vmID>` — the subscriber
// here diffs it against the running set + drives crun to converge :
// pull missing images via ncl, start newly-listed containers, stop
// containers that vanished.
//
// State is pushed whole and applied idempotently (replace-by-name) —
// same model pkg/mounts uses for shares. A missed message self-heals
// on the next publish.
//
// Same Subscriber+ApplyFunc shape as pkg/mounts so any test that
// drove mounts can be cargo-culted to drive containers ; the real
// crun apply lives in Runtime below behind an interface so the
// reconciler is testable without root + cgroups.
package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"

	"github.com/nats-io/nats.go"
	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// Subject is the per-VM event-bus subject container set updates
// arrive on. Mirror of mounts.Subject ; class / fleet fan-out lives
// in the control plane the way teacher → student broadcast does.
func Subject(vmID string) string { return "weft.containers." + vmID }

// Runtime is the crun-driving side the reconciler talks to. Stubbed
// in tests + in dev mode (where containers are simulated as plain
// processes), real impl lives next to the agent's crun bundle path.
type Runtime interface {
	// Pull ensures the image's bundle exists locally. Idempotent on
	// the digest — pulling the same ref twice is a no-op.
	Pull(ctx context.Context, image string) error
	// Start launches the container. Name is the stable handle the
	// diff uses to find this container later.
	Start(ctx context.Context, c pod.WorkloadContainer) error
	// Stop terminates + cleans up the container's bundle.
	Stop(ctx context.Context, name string) error
	// Running returns the names of every container the runtime
	// currently considers alive ; used to seed the diff after a
	// JetStream replay.
	Running(ctx context.Context) ([]string, error)
}

// Reconciler holds the last-applied set so diffs are quick + the
// crun runtime stays the source of truth for "is it actually
// running". Concurrent Apply-safe (one in flight at a time ; later
// publishes during an apply wait).
type Reconciler struct {
	mu      sync.Mutex
	runtime Runtime
	logger  *log.Logger
	desired map[string]pod.WorkloadContainer
}

// NewReconciler builds a Reconciler over runtime. logger may be nil.
func NewReconciler(runtime Runtime, logger *log.Logger) *Reconciler {
	if logger == nil {
		logger = log.Default()
	}
	return &Reconciler{
		runtime: runtime,
		logger:  logger,
		desired: map[string]pod.WorkloadContainer{},
	}
}

// Apply converges the runtime to s. Steps :
//
//  1. validate the payload (rejection on schema bugs)
//  2. compute add / update / drop relative to the previously-applied
//     set (replace-by-name)
//  3. for each add  : pull + start
//     for each update: stop + start (the simplest semantics that
//     covers env / image / command changes)
//     for each drop  : stop
//
// Returns the first error from a step ; subsequent ones still run so
// a single broken container doesn't gate the rest of the set.
func (r *Reconciler) Apply(ctx context.Context, s pod.ContainerSet) error {
	if err := s.Validate(); err != nil {
		return fmt.Errorf("containers: invalid set: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	next := map[string]pod.WorkloadContainer{}
	for _, c := range s.Containers {
		next[c.Name] = c
	}

	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Drops first so a rename (drop + add same name) settles cleanly.
	for name := range r.desired {
		if _, keep := next[name]; keep {
			continue
		}
		r.logger.Printf("containers: stop name=%s", name)
		record(r.runtime.Stop(ctx, name))
	}

	// Stable order so the loom-doctor event stream reads like the
	// publish order — easier to diff a manifest across reconciles.
	names := make([]string, 0, len(next))
	for name := range next {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		want := next[name]
		prev, existed := r.desired[name]
		if existed && containerEqual(prev, want) {
			continue
		}
		if existed {
			r.logger.Printf("containers: restart name=%s reason=spec-changed", name)
			record(r.runtime.Stop(ctx, name))
		}
		r.logger.Printf("containers: pull image=%s name=%s", want.Image, name)
		if err := r.runtime.Pull(ctx, want.Image); err != nil {
			record(fmt.Errorf("pull %s: %w", want.Image, err))
			continue
		}
		r.logger.Printf("containers: start name=%s image=%s", name, want.Image)
		record(r.runtime.Start(ctx, want))
	}

	r.desired = next
	return firstErr
}

// containerEqual is the deep-equal we use to decide if a container
// changed across two publishes. Restart + Annotations are excluded :
// changing annotations alone is not worth a restart, and Restart is
// the supervisor's input — not the container's identity.
func containerEqual(a, b pod.WorkloadContainer) bool {
	if a.Image != b.Image || a.WorkingDir != b.WorkingDir || a.Net != b.Net {
		return false
	}
	if !stringSliceEq(a.Command, b.Command) || !stringSliceEq(a.Args, b.Args) {
		return false
	}
	if len(a.Env) != len(b.Env) {
		return false
	}
	for k, v := range a.Env {
		if b.Env[k] != v {
			return false
		}
	}
	if len(a.Mounts) != len(b.Mounts) {
		return false
	}
	for i := range a.Mounts {
		if a.Mounts[i] != b.Mounts[i] {
			return false
		}
	}
	return true
}

func stringSliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// HandleMessage decodes a published ContainerSet + applies it. Pure
// aside from the injected runtime — same testable shape as pkg/mounts.
func HandleMessage(ctx context.Context, data []byte, r *Reconciler) error {
	var s pod.ContainerSet
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("decode container set: %w", err)
	}
	return r.Apply(ctx, s)
}

// Subscriber listens for this VM's container-set updates + drives the
// reconciler. Direct mirror of mounts.Subscriber down to the JetStream
// last-per-subject replay trick — that's what makes boot-time replay
// of the previously-desired set work, even if loom-server published
// it before the VM was alive.
type Subscriber struct {
	nc     *nats.Conn
	vmID   string
	rec    *Reconciler
	logger *log.Logger
}

const streamName = "weft-containers"

// NewSubscriber wires a Subscriber for vmID against runtime + logger.
func NewSubscriber(nc *nats.Conn, vmID string, runtime Runtime, logger *log.Logger) *Subscriber {
	if logger == nil {
		logger = log.Default()
	}
	return &Subscriber{
		nc:     nc,
		vmID:   vmID,
		rec:    NewReconciler(runtime, logger),
		logger: logger,
	}
}

// Start subscribes to the VM's container-set subject. The returned
// subscription is live until unsubscribed or the connection drops.
// JetStream replay : a stream named `weft-containers` with subjects
// `weft.containers.*` + LastPerSubject retention is the boot-time
// guarantee that the agent picks up the most recent desired set
// even if it was published before the VM existed.
func (s *Subscriber) Start(ctx context.Context) (*nats.Subscription, error) {
	js, err := s.nc.JetStream()
	if err != nil {
		return nil, fmt.Errorf("jetstream: %w", err)
	}
	// Auto-ensure the stream exists ; loom-server provisions it on
	// first publish but a fresh dev env hits this branch the first
	// time the agent boots.
	if _, err := js.StreamInfo(streamName); err != nil {
		if _, err := js.AddStream(&nats.StreamConfig{
			Name:              streamName,
			Subjects:          []string{"weft.containers.*"},
			Retention:         nats.LimitsPolicy,
			MaxMsgsPerSubject: 1,
			Storage:           nats.FileStorage,
		}); err != nil {
			return nil, fmt.Errorf("ensure stream: %w", err)
		}
	}
	sub, err := js.Subscribe(Subject(s.vmID), func(m *nats.Msg) {
		if err := HandleMessage(ctx, m.Data, s.rec); err != nil {
			s.logger.Printf("containers: apply error: %v", err)
		}
		_ = m.Ack()
	}, nats.DeliverLastPerSubject(), nats.AckExplicit())
	if err != nil {
		return nil, fmt.Errorf("subscribe: %w", err)
	}
	return sub, nil
}
