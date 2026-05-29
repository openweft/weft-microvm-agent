//go:build linux

// boot_linux.go — concrete Cloner injected into boot.Runner.
// Shells out to /usr/bin/git for the clone — the ramdisk includes
// it (initrd builds carry git for fetching cloud-init payloads
// anyway). Operators who need go-git-style fetch (no git binary)
// can swap this for a go-git wrapper later ; the Runner.Cloner
// hook is the seam.
package main

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/openweft/weft-vm-agent/pkg/boot"
)

// gitClone is the boot.Runner.Cloner production wiring. Honours ctx
// (caller's timeout / cancel) ; "--depth=1" because first-boot
// provisioning never needs history. "-b" carries the branch / tag
// when SourceRef is set ; for a raw commit sha, "-b" still works
// on modern git.
func gitClone(ctx context.Context, url, ref, dst string) error {
	args := []string{"clone", "--depth=1"}
	if ref != "" {
		args = append(args, "-b", ref)
	}
	args = append(args, url, dst)
	cmd := exec.CommandContext(ctx, "/usr/bin/git", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %v: %s : %w", args, string(out), err)
	}
	return nil
}

// bootRunner is the production wiring of boot.Runner. Centralised
// here so main.go's startup block stays focused on flag parsing.
func bootRunner(workDir, sentinelPath string, logOut interface{ Write([]byte) (int, error) }) *boot.Runner {
	return &boot.Runner{
		WorkDir:      workDir,
		SentinelPath: sentinelPath,
		LogOut:       logOut,
		Cloner:       gitClone,
	}
}
