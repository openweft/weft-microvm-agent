package sshd

import (
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestLoadOrCreateHostKey_FreshGenerate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host_ed25519")
	signer, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if signer == nil {
		t.Fatal("returned signer is nil")
	}
	if signer.PublicKey().Type() != "ssh-ed25519" {
		t.Errorf("type = %q, want ssh-ed25519", signer.PublicKey().Type())
	}
}

func TestLoadOrCreateHostKey_PersistsAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host_ed25519")

	first, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	// Same key on disk → same wire-encoded public key.
	if ssh.FingerprintSHA256(first.PublicKey()) != ssh.FingerprintSHA256(second.PublicKey()) {
		t.Error("host key fingerprint differs across LoadOrCreate calls")
	}
}

func TestLoadOrCreateHostKey_EmptyPathRefused(t *testing.T) {
	if _, err := LoadOrCreateHostKey(""); err == nil {
		t.Error("empty path should fail fast")
	}
}
