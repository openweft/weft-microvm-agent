package metrics

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNew_BuildInfoStamp(t *testing.T) {
	r := New("v1.2.3", "abc123", "2026-05-31T12:00:00Z")
	body := scrape(t, r)
	want := `weft_microvm_agent_build_info{commit="abc123",date="2026-05-31T12:00:00Z",version="v1.2.3"} 1`
	if !strings.Contains(body, want) {
		t.Errorf("/metrics body missing %q\n--- full body :\n%s", want, body)
	}
}

func TestRecordApply_OkIncrementsCounterAndHistogram(t *testing.T) {
	r := New("dev", "none", "unknown")
	r.RecordApply("mesh", nil, 15*time.Millisecond)

	body := scrape(t, r)
	for _, want := range []string{
		`weft_microvm_agent_apply_total{concern="mesh",result="ok"} 1`,
		`weft_microvm_agent_apply_duration_seconds_count{concern="mesh"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics body missing %q\n--- full body :\n%s", want, body)
		}
	}
}

func TestRecordApply_ErrorLabelsResultError(t *testing.T) {
	r := New("dev", "none", "unknown")
	r.RecordApply("mounts", errors.New("mount: device or resource busy"), 7*time.Millisecond)

	body := scrape(t, r)
	if !strings.Contains(body, `weft_microvm_agent_apply_total{concern="mounts",result="error"} 1`) {
		t.Errorf("error result not recorded\n--- full body :\n%s", body)
	}
	// Histogram is concern-only ; an error apply still observes latency
	// (a failed apply takes time we want to see in the band).
	if !strings.Contains(body, `weft_microvm_agent_apply_duration_seconds_count{concern="mounts"} 1`) {
		t.Errorf("error apply latency not observed\n--- full body :\n%s", body)
	}
}

func TestRecordApply_AllConcerns(t *testing.T) {
	r := New("dev", "none", "unknown")
	for _, c := range []string{"mesh", "mounts", "sshkeys", "properties", "boot"} {
		r.RecordApply(c, nil, time.Millisecond)
	}
	body := scrape(t, r)
	for _, c := range []string{"mesh", "mounts", "sshkeys", "properties", "boot"} {
		want := `weft_microvm_agent_apply_total{concern="` + c + `",result="ok"} 1`
		if !strings.Contains(body, want) {
			t.Errorf("/metrics body missing %q", want)
		}
	}
}

func TestSetNATSConnected(t *testing.T) {
	r := New("dev", "none", "unknown")
	if !strings.Contains(scrape(t, r), "weft_microvm_agent_nats_connected 0") {
		t.Error("nats_connected should start at 0")
	}
	r.SetNATSConnected(true)
	if !strings.Contains(scrape(t, r), "weft_microvm_agent_nats_connected 1") {
		t.Error("nats_connected should flip to 1")
	}
	r.SetNATSConnected(false)
	if !strings.Contains(scrape(t, r), "weft_microvm_agent_nats_connected 0") {
		t.Error("nats_connected should flip back to 0")
	}
}

func TestNilReceiverNoPanic(t *testing.T) {
	// Subscribers in tests / non-prod main()s may not wire a recorder ;
	// the helpers must tolerate a nil receiver so callers don't need
	// to nil-check at every call site.
	var r *Recorder
	r.RecordApply("mesh", nil, time.Millisecond)
	r.SetNATSConnected(true)
	r.RecordFirewallStatusPublish(nil)
	r.RecordFirewallDrops(42, 4096)
}

func TestRecordFirewallDrops_MonotonicGrowth(t *testing.T) {
	// Happy path : kernel counter grows monotonically across ticks.
	// Published counter == last observed value (sum of deltas == last).
	r := New("dev", "none", "unknown")
	r.RecordFirewallDrops(0, 0)
	r.RecordFirewallDrops(10, 1024)
	r.RecordFirewallDrops(100, 10240)

	body := scrape(t, r)
	for _, want := range []string{
		"weft_microvm_agent_firewall_drops_packets_total 100",
		"weft_microvm_agent_firewall_drops_bytes_total 10240",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics body missing %q\n--- full body :\n%s", want, body)
		}
	}
}

func TestRecordFirewallDrops_ResetOnKernelRebuild(t *testing.T) {
	// Kernel rebuilds its table (flush + reapply) ; the new counter
	// starts at 0 and grows from there. The Prometheus counter must
	// stay monotonic — accumulate past_total + post_reset_total.
	//
	// Sequence : 100 → 50 → 150.
	// Expected published : 100 (first), 100+50=150 (after reset),
	// 100+150=250 (continuing growth from the rebuilt counter).
	r := New("dev", "none", "unknown")
	r.RecordFirewallDrops(100, 1000)
	r.RecordFirewallDrops(50, 500) // kernel reset detected (50 < 100)
	r.RecordFirewallDrops(150, 1500)

	body := scrape(t, r)
	for _, want := range []string{
		"weft_microvm_agent_firewall_drops_packets_total 250",
		"weft_microvm_agent_firewall_drops_bytes_total 2500",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics body missing %q\n--- full body :\n%s", want, body)
		}
	}
}

func TestRecordFirewallDrops_ResetCaseFromTaskBrief(t *testing.T) {
	// Exact sequence from the task brief : 100 then 50.
	// Expected : 100 + 50 = 150, not 50.
	r := New("dev", "none", "unknown")
	r.RecordFirewallDrops(100, 100)
	r.RecordFirewallDrops(50, 50)

	body := scrape(t, r)
	for _, want := range []string{
		"weft_microvm_agent_firewall_drops_packets_total 150",
		"weft_microvm_agent_firewall_drops_bytes_total 150",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics body missing %q\n--- full body :\n%s", want, body)
		}
	}
}

func TestRecordFirewallDrops_FirstCallSeedsFromZero(t *testing.T) {
	// First-ever observation of a non-zero value : the recorder starts
	// with last=0, so the first call publishes the full value.
	r := New("dev", "none", "unknown")
	r.RecordFirewallDrops(42, 4096)

	body := scrape(t, r)
	for _, want := range []string{
		"weft_microvm_agent_firewall_drops_packets_total 42",
		"weft_microvm_agent_firewall_drops_bytes_total 4096",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics body missing %q\n--- full body :\n%s", want, body)
		}
	}
}

func TestRecordFirewallDrops_FlatTickIsNoop(t *testing.T) {
	// Same value observed twice in a row : no drops happened, counter
	// must not advance.
	r := New("dev", "none", "unknown")
	r.RecordFirewallDrops(10, 100)
	r.RecordFirewallDrops(10, 100)

	body := scrape(t, r)
	for _, want := range []string{
		"weft_microvm_agent_firewall_drops_packets_total 10",
		"weft_microvm_agent_firewall_drops_bytes_total 100",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics body missing %q\n--- full body :\n%s", want, body)
		}
	}
}

func TestRecordFirewallStatusPublish_OkAndError(t *testing.T) {
	r := New("dev", "none", "unknown")
	r.RecordFirewallStatusPublish(nil)
	r.RecordFirewallStatusPublish(nil)
	r.RecordFirewallStatusPublish(errors.New("nats: connection closed"))

	body := scrape(t, r)
	for _, want := range []string{
		`weft_microvm_agent_firewall_status_publishes_total{result="ok"} 2`,
		`weft_microvm_agent_firewall_status_publishes_total{result="error"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics body missing %q\n--- full body :\n%s", want, body)
		}
	}
}

// scrape exercises the /metrics handler in-process and returns the
// response body. Promhttp's text format is stable so substring
// assertions on label-ordered output are safe.
func scrape(t *testing.T, r *Recorder) string {
	t.Helper()
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("/metrics status = %d ; want 200", rec.Code)
	}
	return rec.Body.String()
}
