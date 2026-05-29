package sshkeys

import (
	"encoding/json"
	"testing"
)

func validUpdate(lines ...string) []byte {
	ks := KeySet{}
	for _, l := range lines {
		ks.Keys = append(ks.Keys, Key{PublicKey: l})
	}
	b, _ := json.Marshal(ks)
	return b
}

func TestHandleMessage_AppliesDecodedKeys(t *testing.T) {
	var got KeySet
	err := HandleMessage(validUpdate(
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== alice@laptop",
		"ssh-rsa AAAAB3NzaC1yc2EAAAA= bob@workstation",
	), func(ks KeySet) error {
		got = ks
		return nil
	})
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	if len(got.Keys) != 2 {
		t.Fatalf("apply got %d keys, want 2", len(got.Keys))
	}
	if got.Keys[0].PublicKey == "" {
		t.Errorf("first key empty")
	}
}

func TestHandleMessage_EmptySetIsApplied(t *testing.T) {
	// An empty desired set ("revoke all") MUST reach the apply ;
	// dropping it would leave stale keys authorised.
	called := false
	if err := HandleMessage(validUpdate(), func(ks KeySet) error {
		called = true
		if len(ks.Keys) != 0 {
			t.Errorf("expected 0 keys, got %d", len(ks.Keys))
		}
		return nil
	}); err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	if !called {
		t.Error("apply must run even for an empty set")
	}
}

func TestHandleMessage_RejectsInvalidJSON(t *testing.T) {
	called := false
	if err := HandleMessage([]byte("{not json"), func(KeySet) error { called = true; return nil }); err == nil {
		t.Error("expected decode error")
	}
	if called {
		t.Error("apply must not run on bad JSON")
	}
}

func TestHandleMessage_RejectsMissingType(t *testing.T) {
	bad, _ := json.Marshal(KeySet{Keys: []Key{{PublicKey: "AAAAonly-blob-no-type"}}})
	called := false
	if err := HandleMessage(bad, func(KeySet) error { called = true; return nil }); err == nil {
		t.Error("expected validation error (missing type)")
	}
	if called {
		t.Error("apply must not run on invalid key")
	}
}

func TestHandleMessage_RejectsUnsupportedAlgorithm(t *testing.T) {
	bad, _ := json.Marshal(KeySet{Keys: []Key{{PublicKey: "ssh-unknown AAAA= comment"}}})
	called := false
	if err := HandleMessage(bad, func(KeySet) error { called = true; return nil }); err == nil {
		t.Error("expected validation error (unsupported algorithm)")
	}
	if called {
		t.Error("apply must not run on unknown algorithm")
	}
}

func TestHandleMessage_AcceptsAllStandardAlgorithms(t *testing.T) {
	cases := []string{
		"ssh-rsa AAAA= rsa@h",
		"ssh-ed25519 AAAA= ed@h",
		"ssh-dss AAAA= dss@h",
		"ecdsa-sha2-nistp256 AAAA= 256@h",
		"ecdsa-sha2-nistp384 AAAA= 384@h",
		"ecdsa-sha2-nistp521 AAAA= 521@h",
	}
	for _, line := range cases {
		bad, _ := json.Marshal(KeySet{Keys: []Key{{PublicKey: line}}})
		if err := HandleMessage(bad, func(KeySet) error { return nil }); err != nil {
			t.Errorf("rejected %q: %v", line, err)
		}
	}
}

func TestHandleMessage_AcceptsKeyWithoutComment(t *testing.T) {
	// "<type> <b64>" with no trailing comment is a valid line.
	bad, _ := json.Marshal(KeySet{Keys: []Key{{PublicKey: "ssh-ed25519 AAAAC3="}}})
	if err := HandleMessage(bad, func(KeySet) error { return nil }); err != nil {
		t.Errorf("rejected commentless key: %v", err)
	}
}

func TestHandleMessage_ApplyErrorPropagates(t *testing.T) {
	want := "disk full"
	got := HandleMessage(validUpdate("ssh-ed25519 AAAA= a@b"), func(KeySet) error {
		return errStr(want)
	})
	if got == nil || got.Error() != want {
		t.Errorf("expected %q, got %v", want, got)
	}
}

func TestSubject(t *testing.T) {
	if Subject("vm-123") != "weft.sshkeys.vm-123" {
		t.Errorf("Subject = %q", Subject("vm-123"))
	}
}

// errStr is a tiny helper so we don't import errors just for one literal.
type errStr string

func (e errStr) Error() string { return string(e) }
