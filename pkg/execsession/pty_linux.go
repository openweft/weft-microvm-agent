//go:build linux

package execsession

// pty_linux.go — the production pty pump that drives a /bin/bash
// (or `crun exec`) child + bridges its stdin/stdout to NATS frame
// publishes on weft.exec.<vmID>.<sid>.{in,out}.
//
// Wire shape mirrors loom-server's existing /api/projects/{p}/shell :
//   - in frames : 'i' stdin / 'r' resize(cols u16 + rows u16) / 'x' eof
//   - out frames : 'o' stdout / 'e' exit(code u32)
//
// One pty per session ; ctx cancellation kills the child + tears
// down the in subscription. The Sessions registry holds the cancel
// fn so an out-of-band Close() can preempt a runaway shell.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/creack/pty"
	"github.com/nats-io/nats.go"
)

// PumpConfig bundles everything the pump needs to wire one session.
// Agent main owns the NATS connection + VMID ; this struct is what
// it passes to Run for each incoming open request.
type PumpConfig struct {
	NC      *nats.Conn
	VMID    string
	Request ExecRequest
}

// Run spawns the child + pumps until ctx is done OR the child exits.
// Always emits a final 'e' exit frame so the caller can flip its
// "running" state authoritatively.
func Run(ctx context.Context, cfg PumpConfig) error {
	cmd, err := buildCommand(cfg.Request.Target)
	if err != nil {
		return err
	}
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("pty start: %w", err)
	}
	if cfg.Request.InitialCols > 0 && cfg.Request.InitialRows > 0 {
		_ = pty.Setsize(ptmx, &pty.Winsize{
			Cols: cfg.Request.InitialCols,
			Rows: cfg.Request.InitialRows,
		})
	}

	outSub := SubjectOut(cfg.VMID, cfg.Request.ID)
	inSub := SubjectIn(cfg.VMID, cfg.Request.ID)

	// pty → out subject : every chunk read becomes one frame.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				frame := append([]byte{'o'}, buf[:n]...)
				_ = cfg.NC.Publish(outSub, frame)
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					// best-effort log on the bus — agent main usually
					// also has a logger but we don't want the pump to
					// depend on it.
				}
				return
			}
		}
	}()

	// in subject → pty : decode the 1-byte prefix + dispatch.
	sub, err := cfg.NC.Subscribe(inSub, func(m *nats.Msg) {
		if len(m.Data) == 0 {
			return
		}
		switch m.Data[0] {
		case 'i':
			_, _ = ptmx.Write(m.Data[1:])
		case 'r':
			if len(m.Data) >= 5 {
				cols := binary.BigEndian.Uint16(m.Data[1:3])
				rows := binary.BigEndian.Uint16(m.Data[3:5])
				_ = pty.Setsize(ptmx, &pty.Winsize{Cols: cols, Rows: rows})
			}
		case 'x':
			// Close path : kill the child ; the goroutine above will
			// hit EOF on ptmx.Read and exit cleanly.
			_ = cmd.Process.Kill()
		}
	})
	if err != nil {
		_ = cmd.Process.Kill()
		_ = ptmx.Close()
		return fmt.Errorf("subscribe in: %w", err)
	}
	defer sub.Unsubscribe()

	// Wait for context cancellation OR child exit.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-done
	case <-done:
	}

	exitCode := uint32(0)
	if cmd.ProcessState != nil {
		exitCode = uint32(cmd.ProcessState.ExitCode())
	}
	exitFrame := []byte{'e', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(exitFrame[1:], exitCode)
	_ = cfg.NC.Publish(outSub, exitFrame)
	_ = ptmx.Close()
	return nil
}

// buildCommand picks the right /bin/bash or `crun exec` argv based
// on ExecTarget.Kind.
func buildCommand(t ExecTarget) (*exec.Cmd, error) {
	switch t.Kind {
	case "shell":
		shell := pickShell(t.Command)
		var args []string
		if len(t.Command) > 1 {
			args = append(t.Command[1:], t.Args...)
		} else {
			args = t.Args
		}
		c := exec.Command(shell, args...)
		c.Env = mergeEnv(t.Env)
		c.Dir = workDir(t.WorkDir)
		return c, nil
	case "exec":
		argv := []string{"exec", t.Container}
		argv = append(argv, t.Command...)
		argv = append(argv, t.Args...)
		c := exec.Command("crun", argv...)
		c.Env = mergeEnv(t.Env)
		c.Dir = workDir(t.WorkDir)
		return c, nil
	}
	return nil, fmt.Errorf("buildCommand: unknown kind %q", t.Kind)
}

func mergeEnv(extra map[string]string) []string {
	// We deliberately don't inherit os.Environ() : the guest shell
	// should see a clean env so per-session settings (LANG, TERM,
	// CUBEFS_MNT) are deterministic. The loom-server sets at least
	// TERM=xterm-256color via the open request. PATH MUST include
	// /usr/local/bin so the tool wrappers (pdflatex / marp / …) and
	// crun itself are findable.
	out := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"HOME=/root",
		"LANG=C.UTF-8",
	}
	for k, v := range extra {
		out = append(out, k+"="+v)
	}
	return out
}

func workDir(d string) string {
	// Honour explicit requests but only if the directory actually
	// exists in this VM ; otherwise fall back to /workspace (the
	// shared mount) or / as a last resort. The publisher (loom-
	// server) doesn't know whether the host-side WorkDir hint is
	// valid inside the guest — that's our call.
	for _, candidate := range []string{d, "/workspace", "/tmp", "/"} {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	return "/"
}

// pickShell : honour an explicit override (t.Command[0]), else try
// bash → ash → sh. Alpine guests have /bin/sh (busybox) but no bash ;
// a debian / ubuntu guest has both. The fallback chain keeps the
// shell tab working across rootfs flavours.
func pickShell(command []string) string {
	if len(command) > 0 {
		return command[0]
	}
	for _, candidate := range []string{"/bin/bash", "/bin/ash", "/bin/sh"} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "/bin/sh"
}
