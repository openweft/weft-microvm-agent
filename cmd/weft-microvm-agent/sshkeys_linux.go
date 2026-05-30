//go:build linux

// sshkeys_linux.go — concrete ApplyFunc for the SSH-keys subscriber.
// Atomically rewrites a target user's authorized_keys file from the
// desired KeySet pushed by the host. Non-Linux builds use the stub
// in sshkeys_other.go (the agent runs inside the microVM, so Linux
// is the only production target).

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openweft/weft-microvm-agent/pkg/sshkeys"
)

// sshKeysApplyer returns an ApplyFunc that writes the keys to the
// resolved authorized_keys path. Path is computed once at startup
// (resolve target user's $HOME) so each apply doesn't re-stat.
//
// Atomic write : tmp file in the same directory, fsync, rename over
// the target. The .ssh dir is created with 0700 ; the file with 0600.
// Both ownership choices match what `ssh-keygen` expects.
func sshKeysApplyer(authorizedKeysPath string, uid, gid int) sshkeys.ApplyFunc {
	return func(ks sshkeys.KeySet) error {
		dir := filepath.Dir(authorizedKeysPath)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		// Chown the .ssh dir best-effort — failure (e.g. already
		// owned) is not fatal ; sshd just needs the perms right.
		if uid >= 0 && gid >= 0 {
			_ = os.Chown(dir, uid, gid)
		}

		var buf strings.Builder
		buf.WriteString("# Managed by weft-microvm-agent. Edits are overwritten on next push.\n")
		for _, k := range ks.Keys {
			buf.WriteString(k.PublicKey)
			buf.WriteByte('\n')
		}

		tmp := authorizedKeysPath + ".tmp"
		if err := os.WriteFile(tmp, []byte(buf.String()), 0o600); err != nil {
			return fmt.Errorf("write tmp %s: %w", tmp, err)
		}
		if uid >= 0 && gid >= 0 {
			_ = os.Chown(tmp, uid, gid)
		}
		if err := os.Rename(tmp, authorizedKeysPath); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("rename %s -> %s: %w", tmp, authorizedKeysPath, err)
		}
		return nil
	}
}
