//go:build !linux

// Non-Linux stub : weft-vm-agent only runs inside Linux microVMs in
// production. This stub lets the package compile on a developer's
// macOS so unit tests + `go build ./...` work without a build-tag
// dance every time.
package main

import (
	"errors"

	"github.com/openweft/weft-vm-agent/pkg/sshkeys"
)

func sshKeysApplyer(_ string, _, _ int) sshkeys.ApplyFunc {
	return func(sshkeys.KeySet) error {
		return errors.New("sshkeys apply is Linux-only ; weft-vm-agent runs inside a Linux microVM")
	}
}
