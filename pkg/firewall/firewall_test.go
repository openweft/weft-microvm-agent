package firewall

import (
	"encoding/json"
	"testing"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

func validUpdate() []byte {
	fw := pod.Firewall{
		Rules: []pod.FirewallRule{
			{Direction: "ingress", Protocol: "tcp", PortMin: 22, PortMax: 22},
			{Direction: "ingress", Protocol: "tcp", PortMin: 80, PortMax: 443, RemoteCIDR: "10.0.0.0/24"},
			{Direction: "egress"},
		},
	}
	b, _ := json.Marshal(fw)
	return b
}

func TestHandleMessage_AppliesDecodedRules(t *testing.T) {
	var got *pod.Firewall
	err := HandleMessage(validUpdate(), func(fw *pod.Firewall) error {
		got = fw
		return nil
	})
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	if got == nil {
		t.Fatal("apply was not called")
	}
	if len(got.Rules) != 3 {
		t.Fatalf("decoded rules = %d, want 3", len(got.Rules))
	}
	if got.Rules[1].RemoteCIDR != "10.0.0.0/24" {
		t.Errorf("rule[1].RemoteCIDR = %q", got.Rules[1].RemoteCIDR)
	}
}

func TestHandleMessage_RejectsInvalidJSON(t *testing.T) {
	called := false
	err := HandleMessage([]byte("{not json"), func(*pod.Firewall) error { called = true; return nil })
	if err == nil {
		t.Error("expected decode error")
	}
	if called {
		t.Error("apply must not run on bad JSON")
	}
}

func TestHandleMessage_RejectsInvalidRule(t *testing.T) {
	bad, _ := json.Marshal(pod.Firewall{Rules: []pod.FirewallRule{{Direction: "bogus"}}})
	called := false
	if err := HandleMessage(bad, func(*pod.Firewall) error { called = true; return nil }); err == nil {
		t.Error("expected validation error")
	}
	if called {
		t.Error("apply must not run on invalid rule")
	}
}

func TestHandleMessage_EmptyRulesetIsValid(t *testing.T) {
	// Empty publish means "default policy only" — the agent must apply
	// it (i.e. flush down to the default chain policy), not reject it.
	empty, _ := json.Marshal(pod.Firewall{})
	called := false
	err := HandleMessage(empty, func(fw *pod.Firewall) error {
		called = true
		if len(fw.Rules) != 0 {
			t.Errorf("expected empty rules, got %d", len(fw.Rules))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	if !called {
		t.Error("apply must run on empty (well-formed) update")
	}
}

func TestSubject(t *testing.T) {
	if Subject("vm-123") != "weft.firewall.vm-123" {
		t.Errorf("Subject = %q", Subject("vm-123"))
	}
}
