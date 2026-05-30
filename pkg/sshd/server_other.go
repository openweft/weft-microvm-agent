//go:build !linux

// Non-Linux stub : weft-vm-agent runs inside Linux microVMs in
// production. The PTY plumbing in server.go (creack/pty + syscall
// SysProcAttr.Setsid/Setctty) is Linux-only ; on macOS the package
// compiles to this stub so `go build ./...` works during dev.

package sshd

import (
	"errors"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

type Server struct {
	AuthStore *AuthStore
	HostKey   ssh.Signer
	Shell     string
	Logger    *log.Logger
}

func NewServer(store *AuthStore, hostKey ssh.Signer, shell string, logger *log.Logger) (*Server, error) {
	return &Server{AuthStore: store, HostKey: hostKey, Shell: shell, Logger: logger}, nil
}

func (*Server) Serve(net.Listener) error {
	return errors.New("sshd is Linux-only ; weft-vm-agent runs inside a Linux microVM")
}
