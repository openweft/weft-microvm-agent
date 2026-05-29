//go:build linux

// server.go — minimal interactive-shell SSH server. Accepts session
// channels only ; refuses port-forwarding, X11, agent-forwarding,
// SFTP. The use case is ops shell into the VM, nothing fancier.
// Operators who need SFTP push files via `weft vm push` or NCL
// share mounts ; both already exist.
//
// Auth : public-key only, against the AuthStore (kept fresh by the
// pkg/sshkeys NATS subscriber). No password fallback ; if the
// keys aren't in the store the connection is refused.
//
// Shell : forks the configured binary (typically /bin/sh) in a PTY,
// with `window-change` requests proxied to pty.Setsize so vim and
// friends behave. Channel writes pipe through to the PTY master ;
// PTY output pipes back. Stop conditions : either side closes ;
// the child exits ; the connection drops.

package sshd

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// Server is the per-VM SSH listener. Construct via NewServer ; call
// Serve on a net.Listener (which the caller binds to wg0:2222 in
// production).
type Server struct {
	// AuthStore is consulted on every PublicKeyCallback. Must be
	// non-nil ; an empty store means "no key authorised" (every
	// connection refused).
	AuthStore *AuthStore
	// HostKey is the server's identity. Generate via
	// LoadOrCreateHostKey ; the same key across reboots makes
	// known_hosts entries durable.
	HostKey ssh.Signer
	// Shell is the path the session execs in a PTY. /bin/sh by
	// convention ; operator can override (e.g. /bin/ash on Alpine).
	Shell string
	// Logger receives connection + error lines. Defaults to the
	// stdlib log when nil.
	Logger *log.Logger
}

// NewServer fails when any required field is unset. The early-fail
// pattern beats discovering it on first connection.
func NewServer(store *AuthStore, hostKey ssh.Signer, shell string, logger *log.Logger) (*Server, error) {
	if store == nil {
		return nil, errors.New("nil AuthStore")
	}
	if hostKey == nil {
		return nil, errors.New("nil HostKey")
	}
	if shell == "" {
		shell = "/bin/sh"
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Server{AuthStore: store, HostKey: hostKey, Shell: shell, Logger: logger}, nil
}

// config builds the ssh.ServerConfig with the PublicKeyCallback
// wired through the AuthStore. Recomputed per-Serve so a long-
// running Server picks up auth-store changes (Replace) without
// re-construction.
func (s *Server) config() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			name, ok := s.AuthStore.Authorize(key)
			if !ok {
				return nil, fmt.Errorf("ssh: key %s not in AuthStore", ssh.FingerprintSHA256(key))
			}
			return &ssh.Permissions{
				Extensions: map[string]string{
					"weft-key-name":        name,
					"weft-key-fingerprint": ssh.FingerprintSHA256(key),
				},
			}, nil
		},
		ServerVersion: "SSH-2.0-weft-vm-agent",
	}
	cfg.AddHostKey(s.HostKey)
	return cfg
}

// Serve accepts on ln until it errors (closed listener -> return
// nil). Each accepted connection runs in its own goroutine ; errors
// at the per-connection layer are logged, never propagated to
// Serve's return.
func (s *Server) Serve(ln net.Listener) error {
	s.Logger.Printf("sshd: listening on %s (auth keys: %d)", ln.Addr(), s.AuthStore.Size())
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(nc net.Conn) {
	defer nc.Close()
	sc, chans, reqs, err := ssh.NewServerConn(nc, s.config())
	if err != nil {
		s.Logger.Printf("sshd: handshake from %s: %v", nc.RemoteAddr(), err)
		return
	}
	defer sc.Close()

	keyName := ""
	if sc.Permissions != nil {
		keyName = sc.Permissions.Extensions["weft-key-name"]
	}
	s.Logger.Printf("sshd: %s connected as %s (key: %s)", nc.RemoteAddr(), sc.User(), keyName)

	// We don't honour any global request (no port-forwarding, no
	// keepalive responder beyond what go's crypto/ssh handles
	// natively). Discarding the channel is the documented "ignore"
	// pattern.
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "weft-vm-agent only supports session channels")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			s.Logger.Printf("sshd: accept channel: %v", err)
			continue
		}
		go s.handleSession(ch, chReqs)
	}
}

// handleSession owns one accepted session channel : waits for
// pty-req + shell (or exec), spawns the shell in a PTY, proxies
// I/O, exits when either side closes.
func (s *Server) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()

	// State accumulated by pre-shell requests. We don't start the
	// PTY until the `shell` (or `exec`) request lands so we honour
	// the window size + env from `pty-req` + `env` first.
	var (
		ptyReq    *ptyReqPayload
		envVars   []string
		execLine  string
		ptyMaster *os.File
		started   bool
		startMu   sync.Mutex
	)

	for req := range reqs {
		switch req.Type {
		case "pty-req":
			p, err := parsePtyReq(req.Payload)
			if err != nil {
				_ = req.Reply(false, nil)
				s.Logger.Printf("sshd: pty-req parse: %v", err)
				continue
			}
			ptyReq = &p
			_ = req.Reply(true, nil)
		case "env":
			if k, v, err := parseEnvReq(req.Payload); err == nil {
				envVars = append(envVars, k+"="+v)
			}
			_ = req.Reply(true, nil)
		case "shell":
			startMu.Lock()
			if started {
				startMu.Unlock()
				_ = req.Reply(false, nil)
				continue
			}
			started = true
			startMu.Unlock()
			f, err := s.startShell(ch, ptyReq, envVars, "")
			if err != nil {
				s.Logger.Printf("sshd: start shell: %v", err)
				_ = req.Reply(false, nil)
				return
			}
			ptyMaster = f
			_ = req.Reply(true, nil)
		case "exec":
			startMu.Lock()
			if started {
				startMu.Unlock()
				_ = req.Reply(false, nil)
				continue
			}
			started = true
			startMu.Unlock()
			line, err := parseExecReq(req.Payload)
			if err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			execLine = line
			f, err := s.startShell(ch, ptyReq, envVars, execLine)
			if err != nil {
				s.Logger.Printf("sshd: start exec %q: %v", execLine, err)
				_ = req.Reply(false, nil)
				return
			}
			ptyMaster = f
			_ = req.Reply(true, nil)
		case "window-change":
			if ptyMaster != nil {
				if w, err := parseWinChReq(req.Payload); err == nil {
					_ = pty.Setsize(ptyMaster, &pty.Winsize{
						Rows: uint16(w.rows), Cols: uint16(w.cols),
						X: uint16(w.xPx), Y: uint16(w.yPx),
					})
				}
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// startShell forks Shell (or `Shell -c <execLine>`) attached to a
// PTY, plumbs the channel <-> PTY master, returns the master so
// window-change can resize it.
func (s *Server) startShell(ch ssh.Channel, ptyReq *ptyReqPayload, envVars []string, execLine string) (*os.File, error) {
	args := []string{}
	if execLine != "" {
		args = []string{"-c", execLine}
	}
	cmd := exec.Command(s.Shell, args...)

	// Environment : the SSH "env" requests are typically rejected
	// by real sshds by default ; we accept them but inherit the
	// agent's environ as the base. Operators wanting to lock this
	// down further can run the shell behind a wrapper.
	cmd.Env = append(os.Environ(), envVars...)
	if ptyReq != nil && ptyReq.term != "" {
		cmd.Env = append(cmd.Env, "TERM="+ptyReq.term)
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}

	winsize := &pty.Winsize{Rows: 24, Cols: 80}
	if ptyReq != nil {
		winsize.Rows = uint16(ptyReq.rows)
		winsize.Cols = uint16(ptyReq.cols)
	}
	f, err := pty.StartWithSize(cmd, winsize)
	if err != nil {
		return nil, err
	}

	// Proxy the channel <-> PTY master. Two goroutines, exit when
	// either side closes ; the second copy returning signals the
	// parent to wait the child + send the exit-status request.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(f, ch); done <- struct{}{} }()
	go func() { _, _ = io.Copy(ch, f); done <- struct{}{} }()

	go func() {
		<-done
		// One direction closed ; close the PTY to wake the other
		// copy and reap the child.
		_ = f.Close()
		<-done
		state, _ := cmd.Process.Wait()
		exit := uint32(0)
		if state != nil {
			exit = uint32(state.ExitCode())
		}
		// SSH "exit-status" : 4-byte big-endian uint32 payload.
		payload := []byte{byte(exit >> 24), byte(exit >> 16), byte(exit >> 8), byte(exit)}
		_, _ = ch.SendRequest("exit-status", false, payload)
		_ = ch.Close()
	}()

	return f, nil
}

// --- request payload parsers ----------------------------------------

type ptyReqPayload struct {
	term       string
	cols, rows uint32
	xPx, yPx   uint32
	// modes (terminal mode encoding) ignored ; pty inherits.
}

func parsePtyReq(p []byte) (ptyReqPayload, error) {
	var r ptyReqPayload
	term, rest, ok := unmarshalString(p)
	if !ok {
		return r, errors.New("pty-req: missing TERM")
	}
	r.term = term
	if len(rest) < 16 {
		return r, errors.New("pty-req: short")
	}
	r.cols = beUint32(rest[0:4])
	r.rows = beUint32(rest[4:8])
	r.xPx = beUint32(rest[8:12])
	r.yPx = beUint32(rest[12:16])
	return r, nil
}

func parseEnvReq(p []byte) (string, string, error) {
	k, rest, ok := unmarshalString(p)
	if !ok {
		return "", "", errors.New("env: missing key")
	}
	v, _, ok := unmarshalString(rest)
	if !ok {
		return "", "", errors.New("env: missing value")
	}
	return k, v, nil
}

func parseExecReq(p []byte) (string, error) {
	line, _, ok := unmarshalString(p)
	if !ok {
		return "", errors.New("exec: missing command")
	}
	return line, nil
}

type winChPayload struct {
	cols, rows uint32
	xPx, yPx   uint32
}

func parseWinChReq(p []byte) (winChPayload, error) {
	var w winChPayload
	if len(p) < 16 {
		return w, errors.New("window-change: short")
	}
	w.cols = beUint32(p[0:4])
	w.rows = beUint32(p[4:8])
	w.xPx = beUint32(p[8:12])
	w.yPx = beUint32(p[12:16])
	return w, nil
}

// SSH wire helpers : strings are length-prefixed (4-byte BE) byte
// sequences. The whole binary protocol uses this shape, but for
// our two payload parsers it's only a couple of fields.
func unmarshalString(b []byte) (s string, rest []byte, ok bool) {
	if len(b) < 4 {
		return "", b, false
	}
	n := beUint32(b[:4])
	if uint32(len(b)) < 4+n {
		return "", b, false
	}
	return string(b[4 : 4+n]), b[4+n:], true
}

func beUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
