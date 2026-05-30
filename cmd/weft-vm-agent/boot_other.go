//go:build !linux

package main

import "github.com/openweft/weft-vm-agent/pkg/boot"

func bootRunner(workDir, sentinelPath string, logOut interface{ Write([]byte) (int, error) }) *boot.Runner {
	// macOS dev build : leave Cloner nil. Runner returns a clear
	// error if it ever sees SourceKind=="git" ; the rest of the
	// surface (script-only) still works.
	return &boot.Runner{
		WorkDir:      workDir,
		SentinelPath: sentinelPath,
		LogOut:       logOut,
	}
}
