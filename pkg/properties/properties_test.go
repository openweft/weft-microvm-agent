package properties

import (
	"encoding/json"
	"testing"
)

func encode(p map[string]string) []byte {
	b, _ := json.Marshal(PropertySet{Properties: p})
	return b
}

func TestHandleMessage_AppliesDecodedMap(t *testing.T) {
	var got PropertySet
	err := HandleMessage(encode(map[string]string{
		"owner":            "team-alpha",
		"weft.boot/script": "#!/bin/sh\necho hi\n",
	}), func(ps PropertySet) error {
		got = ps
		return nil
	})
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	if got.Properties["owner"] != "team-alpha" {
		t.Errorf("owner = %q", got.Properties["owner"])
	}
	if got.Properties["weft.boot/script"] == "" {
		t.Errorf("weft.boot/script missing")
	}
}

func TestHandleMessage_EmptyMapIsApplied(t *testing.T) {
	called := false
	if err := HandleMessage(encode(map[string]string{}), func(ps PropertySet) error {
		called = true
		if len(ps.Properties) != 0 {
			t.Errorf("expected 0 properties, got %d", len(ps.Properties))
		}
		return nil
	}); err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	if !called {
		t.Error("apply must run even for an empty set (clear semantics)")
	}
}

func TestHandleMessage_RejectsInvalidJSON(t *testing.T) {
	called := false
	if err := HandleMessage([]byte("{nope"), func(PropertySet) error { called = true; return nil }); err == nil {
		t.Error("expected decode error")
	}
	if called {
		t.Error("apply must not run on bad JSON")
	}
}

func TestValidate_RejectsEmptyKey(t *testing.T) {
	if err := (PropertySet{Properties: map[string]string{"": "v"}}).Validate(); err == nil {
		t.Error("expected error for empty key")
	}
}

func TestValidate_RejectsAbsolutePath(t *testing.T) {
	if err := (PropertySet{Properties: map[string]string{"/etc/shadow": "no"}}).Validate(); err == nil {
		t.Error("expected error for absolute key")
	}
}

func TestValidate_RejectsTraversal(t *testing.T) {
	for _, k := range []string{"../escape", "weft.boot/../escape", "..", "a/../b"} {
		if err := (PropertySet{Properties: map[string]string{k: "v"}}).Validate(); err == nil {
			t.Errorf("expected error for %q (traversal)", k)
		}
	}
}

func TestValidate_RejectsNUL(t *testing.T) {
	if err := (PropertySet{Properties: map[string]string{"a\x00b": "v"}}).Validate(); err == nil {
		t.Error("expected error for key containing NUL")
	}
}

func TestValidate_AcceptsNamespacedKeys(t *testing.T) {
	ps := PropertySet{Properties: map[string]string{
		"owner":                 "team-alpha",
		"weft.boot/source.kind": "git",
		"weft.boot/source.url":  "https://example.com/repo.git",
		"weft.boot/script":      "#!/bin/sh\necho ok\n",
		"app.example.com/tier":  "prod",
	}}
	if err := ps.Validate(); err != nil {
		t.Errorf("rejected legitimate keys: %v", err)
	}
}

func TestHandleMessage_ApplyErrorPropagates(t *testing.T) {
	want := "disk full"
	got := HandleMessage(encode(map[string]string{"k": "v"}), func(PropertySet) error {
		return errStr(want)
	})
	if got == nil || got.Error() != want {
		t.Errorf("expected %q, got %v", want, got)
	}
}

func TestSubject(t *testing.T) {
	if Subject("vm-9") != "weft.properties.vm-9" {
		t.Errorf("Subject = %q", Subject("vm-9"))
	}
}

type errStr string

func (e errStr) Error() string { return string(e) }
