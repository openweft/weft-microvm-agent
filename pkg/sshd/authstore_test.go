package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/openweft/weft-microvm-agent/pkg/sshkeys"
	"golang.org/x/crypto/ssh"
)

// makeKey returns a freshly-minted ed25519 ssh.PublicKey + its
// "<type> <b64> <comment>" line ; used to feed both ends of
// AuthStore tests with consistent material.
func makeKey(t *testing.T, comment string) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := string(ssh.MarshalAuthorizedKey(sshPub))
	// MarshalAuthorizedKey returns "<type> <b64>\n" ; tack on the
	// comment to mimic what the host-side catalogue would produce.
	line = line[:len(line)-1] + " " + comment + "\n"
	return sshPub, line
}

func TestAuthStore_AuthorizeMatchesReplacedSet(t *testing.T) {
	store := NewAuthStore()
	pub, line := makeKey(t, "alice@laptop")

	if _, ok := store.Authorize(pub); ok {
		t.Error("empty store must refuse")
	}

	store.Replace(sshkeys.KeySet{Keys: []sshkeys.Key{{PublicKey: line}}})
	if store.Size() != 1 {
		t.Errorf("size = %d, want 1", store.Size())
	}
	name, ok := store.Authorize(pub)
	if !ok {
		t.Fatal("Authorize should accept the replaced key")
	}
	if name != "alice@laptop" {
		t.Errorf("name = %q, want %q", name, "alice@laptop")
	}
}

func TestAuthStore_ReplaceEvictsOld(t *testing.T) {
	store := NewAuthStore()
	old, oldLine := makeKey(t, "old@host")
	new1, newLine := makeKey(t, "new@host")

	store.Replace(sshkeys.KeySet{Keys: []sshkeys.Key{{PublicKey: oldLine}}})
	if _, ok := store.Authorize(old); !ok {
		t.Fatal("old key should match initially")
	}
	// Push a new set that doesn't include old.
	store.Replace(sshkeys.KeySet{Keys: []sshkeys.Key{{PublicKey: newLine}}})
	if _, ok := store.Authorize(old); ok {
		t.Error("old key must be evicted after Replace")
	}
	if _, ok := store.Authorize(new1); !ok {
		t.Error("new key should match after Replace")
	}
}

func TestAuthStore_EmptySetRevokes(t *testing.T) {
	store := NewAuthStore()
	pub, line := makeKey(t, "soon-gone")
	store.Replace(sshkeys.KeySet{Keys: []sshkeys.Key{{PublicKey: line}}})
	if _, ok := store.Authorize(pub); !ok {
		t.Fatal("seeded key should match")
	}
	store.Replace(sshkeys.KeySet{})
	if _, ok := store.Authorize(pub); ok {
		t.Errorf("empty Replace must revoke ; size = %d", store.Size())
	}
	if store.Size() != 0 {
		t.Errorf("size = %d, want 0", store.Size())
	}
}

func TestAuthStore_UnparseableLineRejected(t *testing.T) {
	store := NewAuthStore()
	acc, rej := store.Replace(sshkeys.KeySet{Keys: []sshkeys.Key{
		{PublicKey: "ssh-ed25519 NOT-VALID-BASE64 comment"},
		{PublicKey: "garbage with no shape"},
	}})
	if acc != 0 || rej != 2 {
		t.Errorf("accepted=%d rejected=%d, want 0/2", acc, rej)
	}
	if store.Size() != 0 {
		t.Error("store should reject all unparseable lines")
	}
}

func TestAuthStore_MixedValidAndBogus(t *testing.T) {
	store := NewAuthStore()
	good, goodLine := makeKey(t, "ok@host")
	acc, rej := store.Replace(sshkeys.KeySet{Keys: []sshkeys.Key{
		{PublicKey: goodLine},
		{PublicKey: "ssh-rsa not-real comment"},
	}})
	if acc != 1 || rej != 1 {
		t.Errorf("accepted=%d rejected=%d, want 1/1", acc, rej)
	}
	if _, ok := store.Authorize(good); !ok {
		t.Error("good key should still match after a mixed push")
	}
}
