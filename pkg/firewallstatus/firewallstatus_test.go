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

	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
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

func startNATS(t *testing.T) (*natsserver.Server, string) {
	t.Helper()
	opts := natstest.DefaultTestOptions
	opts.Port = -1
	srv := natstest.RunServer(&opts)
	return srv, srv.ClientURL()
}
