package firewallstatus

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

func TestSubject(t *testing.T) {
	if Subject("vm-7") != "weft.firewall.vm-7.status" {
		t.Errorf("Subject = %q", Subject("vm-7"))
	}
}

func TestNew_Validates(t *testing.T) {
	cases := []struct {
		name string
		fn   func() error
	}{
		{"nil conn", func() error { _, err := New(nil, "vm", okRead, time.Second, nil); return err }},
		{"empty vmID", func() error { _, err := New(&nats.Conn{}, "", okRead, time.Second, nil); return err }},
		{"nil read", func() error { _, err := New(&nats.Conn{}, "vm", nil, time.Second, nil); return err }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.fn(); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestRun_PublishesOnTickAndImmediate(t *testing.T) {
	srv, url := startNATS(t)
	defer srv.Shutdown()

	nc := connectNATS(t, url)
	defer nc.Close()

	// Reader counts calls and varies the rule count so successive
	// publishes are distinguishable in the assertion.
	var mu sync.Mutex
	var calls int
	read := func() pod.FirewallStatus {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return pod.FirewallStatus{Overall: "Healthy", TableInstalled: true, RulesInstalled: calls}
	}

	em, err := New(nc, "vm-1", read, 30*time.Millisecond, silentLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	em.now = func() time.Time { return time.Unix(1700000000, 0) }

	received := make(chan pod.FirewallStatus, 4)
	sub, err := nc.Subscribe("weft.firewall.vm-1.status", func(m *nats.Msg) {
		var s pod.FirewallStatus
		if err := json.Unmarshal(m.Data, &s); err != nil {
			t.Errorf("decode: %v", err)
			return
		}
		select {
		case received <- s:
		default:
		}
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	ctx, cancel := context.WithCancel(context.Background())
	go em.Run(ctx)

	first := waitFor(t, received, 500*time.Millisecond)
	if first.Overall != "Healthy" || !first.TableInstalled || first.RulesInstalled != 1 {
		t.Errorf("first status wrong: %+v", first)
	}
	if first.PublishedAtUnix != 1700000000 {
		t.Errorf("stamp not applied: %d", first.PublishedAtUnix)
	}

	second := waitFor(t, received, 500*time.Millisecond)
	if second.RulesInstalled != 2 {
		t.Errorf("second status rules = %d, want 2", second.RulesInstalled)
	}

	cancel()
}

func TestSetMetricsHook_FiresOnEveryPublish(t *testing.T) {
	srv, url := startNATS(t)
	defer srv.Shutdown()

	nc := connectNATS(t, url)
	defer nc.Close()

	em, err := New(nc, "vm-hook", okRead, 30*time.Millisecond, silentLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Hook captures every err the Emitter sees ; an unbuffered channel
	// would deadlock the publish loop, so we use a buffered slot and
	// drain it from the goroutine running the assertions.
	hookCalls := make(chan error, 8)
	em.SetMetricsHook(func(err error) {
		select {
		case hookCalls <- err:
		default:
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	go em.Run(ctx)

	// Wait for two hook invocations : the immediate Run-entry publish
	// + the first ticker tick. Both should report nil error against
	// a live NATS server.
	for i := 0; i < 2; i++ {
		select {
		case err := <-hookCalls:
			if err != nil {
				t.Errorf("hook[%d] err = %v, want nil", i, err)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("hook[%d]: timed out waiting", i)
		}
	}
	cancel()
}

func TestSetReadHook_FiresWithDropCountersFromRead(t *testing.T) {
	srv, url := startNATS(t)
	defer srv.Shutdown()

	nc := connectNATS(t, url)
	defer nc.Close()

	// ReadFunc returns increasing drop counters across calls so the
	// hook captures distinct (packets, bytes) pairs.
	var mu sync.Mutex
	var calls int
	read := func() pod.FirewallStatus {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return pod.FirewallStatus{
			Overall:      "Healthy",
			DropsPackets: uint64(calls * 10),
			DropsBytes:   uint64(calls * 1024),
		}
	}

	em, err := New(nc, "vm-readhook", read, 30*time.Millisecond, silentLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	type sample struct{ pkts, byts uint64 }
	samples := make(chan sample, 8)
	em.SetReadHook(func(p, b uint64) {
		select {
		case samples <- sample{p, b}:
		default:
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	go em.Run(ctx)

	// First read = 10 / 1024 ; second tick = 20 / 2048.
	for i, want := range []sample{{10, 1024}, {20, 2048}} {
		select {
		case got := <-samples:
			if got != want {
				t.Errorf("readhook[%d] = %+v, want %+v", i, got, want)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("readhook[%d]: timed out waiting", i)
		}
	}
	cancel()
}

func TestSetReadHook_NilIsSafe(t *testing.T) {
	// publishOnce without a ReadHook must not panic. Default Emitter
	// leaves readHook nil ; the publish loop has to gate on it.
	srv, url := startNATS(t)
	defer srv.Shutdown()
	nc := connectNATS(t, url)
	defer nc.Close()

	em, err := New(nc, "vm-nilread", okRead, time.Hour, silentLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = em.Run(ctx) // no panic = pass
}

func TestSetMetricsHook_NilHookIsSafe(t *testing.T) {
	// Default Emitter has no hook ; publishOnce must not panic. We
	// exercise it directly (bypassing Run's ticker) by leaving the
	// emitter's nc nil on the publish step is unsafe — instead we
	// use a live NATS conn but skip the hook wiring.
	srv, url := startNATS(t)
	defer srv.Shutdown()
	nc := connectNATS(t, url)
	defer nc.Close()

	em, err := New(nc, "vm-nilhook", okRead, time.Hour, silentLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// No SetMetricsHook call : the hook field stays nil. publishOnce
	// must run cleanly. We call it directly via Run so we cover the
	// defer block too.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = em.Run(ctx) // returns when ctx fires ; no panic = pass
}

func waitFor(t *testing.T, ch <-chan pod.FirewallStatus, d time.Duration) pod.FirewallStatus {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(d):
		t.Fatalf("timed out waiting for status")
		return pod.FirewallStatus{}
	}
}

func okRead() pod.FirewallStatus { return pod.FirewallStatus{Overall: "Healthy"} }
func silentLog() *log.Logger     { return log.New(os.NewFile(0, os.DevNull), "", 0) }

// connectNATS dials the test server with a timeout an emulated machine can
// meet.
//
// nats.Connect defaults to a 2s connect timeout, which is ample natively and is
// not under qemu-user: the ppc64le lane failed here with "no servers available
// for connection" while amd64 and s390x passed the same package. The server is
// definitely listening by then -- natstest.RunServer waits on
// ReadyForConnections(10s) and panics if it is not -- so the deadline is the
// client's, and raising it weakens no assertion: the connection must still
// succeed.
func connectNATS(t *testing.T, url string) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(url, nats.Timeout(30*time.Second))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return nc
}

func startNATS(t *testing.T) (*natsserver.Server, string) {
	t.Helper()
	opts := natstest.DefaultTestOptions
	opts.Port = -1
	srv := natstest.RunServer(&opts)
	return srv, srv.ClientURL()
}
