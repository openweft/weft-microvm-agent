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
