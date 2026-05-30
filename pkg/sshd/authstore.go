// Package sshd is the embedded SSH server that runs inside the
// microVM (in the ramdisk's weft-microvm-agent process). Replaces the
// "depend on whatever sshd ships in the container image" approach :
// Docker / scratch / distroless images don't carry sshd, so ops
// access via SSH would otherwise require the workload owner to
// bake one in. With this server, ops always reach the VM via a
// dedicated :2222 listener on wg0, regardless of what's inside the
// container.
//
// Auth is wired through the AuthStore declared here — the existing
// pkg/sshkeys subscriber (commit 032f346) keeps it fresh via NATS
// pushes ; the sshd reads from it on every connection. No
// authorized_keys file in the loop ; the source of truth is the
// in-memory store.
//
// Shell exec'd is the VM's own shell (PID-1 namespace), not the
// container's. Clean separation : SSH = the VM's runtime, `weft-microvm
// exec <container> sh` = the workload. Operators get both axes.
package sshd

import (
	"sync"

	"github.com/openweft/weft-microvm-agent/pkg/sshkeys"
	"golang.org/x/crypto/ssh"
)

// AuthStore holds the current authorised public keys for the VM.
// Updated atomically (replace-set) by the sshkeys subscriber on
// every NATS push ; queried by the sshd's PublicKeyCallback on
// every connection. The lookup map is keyed by the SSH wire-format
// fingerprint of the key (ssh.FingerprintSHA256) for O(1) match.
//
// Empty store = no key authorised, which is a legitimate "revoked
// all" state — every connection is refused.
type AuthStore struct {
	mu sync.RWMutex
	// byFingerprint maps "SHA256:<b64>" → the parsed PublicKey.
	// Storing the parsed form here means PublicKeyCallback doesn't
	// re-parse on every auth attempt.
	byFingerprint map[string]ssh.PublicKey
	// names maps the same fingerprint to the catalogue-side comment
	// (or whatever the OpenSSH line carried). Used in log lines so
	// "alice@laptop just SSH'd" is more useful than the raw blob.
	names map[string]string
}

// NewAuthStore returns an empty store. The first Replace populates
// it ; until then every Authorize returns false.
func NewAuthStore() *AuthStore {
	return &AuthStore{
		byFingerprint: map[string]ssh.PublicKey{},
		names:         map[string]string{},
	}
}

// Replace swaps the authorised set for the contents of ks. Atomic at
// the store level — concurrent Authorize calls either see the old
// or the new set, never a partial mix. Unparseable lines are
// silently dropped (the host-side catalogue should have caught them
// already ; this is the guest's defence in depth).
//
// Returns the count of accepted keys + the count of rejected lines
// so the subscriber's log can surface a partial push.
func (s *AuthStore) Replace(ks sshkeys.KeySet) (accepted, rejected int) {
	fresh := map[string]ssh.PublicKey{}
	freshNames := map[string]string{}
	for _, k := range ks.Keys {
		pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(k.PublicKey))
		if err != nil {
			rejected++
			continue
		}
		fp := ssh.FingerprintSHA256(pub)
		fresh[fp] = pub
		freshNames[fp] = comment
		accepted++
	}
	s.mu.Lock()
	s.byFingerprint = fresh
	s.names = freshNames
	s.mu.Unlock()
	return accepted, rejected
}

// Authorize answers "is this public key in the current set?". On
// match, returns the human-readable name (the OpenSSH comment) so
// the caller can log "session opened by <name>".
//
// Equality is by fingerprint — comparing ssh.PublicKey values
// directly would be byte-by-byte over the wire encoding, which is
// what the fingerprint already covers.
func (s *AuthStore) Authorize(key ssh.PublicKey) (name string, ok bool) {
	fp := ssh.FingerprintSHA256(key)
	s.mu.RLock()
	pub, found := s.byFingerprint[fp]
	n := s.names[fp]
	s.mu.RUnlock()
	if !found {
		return "", false
	}
	// Belt-and-braces : confirm the marshalled forms match, in case
	// of a fingerprint collision (cryptographically infeasible, but
	// the code is small enough to make the check anyway).
	if string(pub.Marshal()) != string(key.Marshal()) {
		return "", false
	}
	return n, true
}

// Size returns the number of currently-authorised keys. Useful for
// log lines + the sshd's "ready" announcement.
func (s *AuthStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byFingerprint)
}
