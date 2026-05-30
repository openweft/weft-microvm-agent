// Package boot is the first-boot provisioning runner. The host
// stamps four reserved properties on the VM at create time
// (weft.boot/source.kind, source.url, source.ref, script — see
// openweft/weft-webui commit 2c098e7) ; the pkg/properties
// subscriber mirrors them to /run/weft/properties/weft.boot/* ;
// THIS package reads from there, pulls the payload, runs the
// script. One-shot per VM ; idempotent via a sentinel file so
// reboots don't re-provision.
//
// Why piggyback on properties instead of a dedicated NATS
// subject : keeps the host-side wire simple (the host already
// publishes weft.boot/* with the property subscriber's
// publishes ; a separate subject would duplicate that). Also
// gives the Properties drawer tab visibility into what was
// stamped — operator can audit the boot config without a
// separate panel.
//
// Script execution uses mvdan.cc/sh/v3 (POSIX sh in Go) so the
// payload doesn't need to ship /bin/sh in its image — works for
// scratch / distroless / alpine alike. git clone shells out to
// /usr/bin/git when present (the ramdisk includes it) ; OCI pull
// is documented as a follow-on (oras-go integration).
package boot

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// Config is the resolved boot request : what to pull + what to run.
// All fields optional ; an empty Config is a no-op (the runner logs
// "no provisioning requested" and stamps the sentinel anyway, so a
// reboot doesn't keep checking).
type Config struct {
	SourceKind string // "" | "git" | "oci"
	SourceURL  string
	SourceRef  string // branch / tag / commit / digest
	Script     string // POSIX sh body
}

// IsEmpty reports whether the operator stamped no boot request.
// Empty kind + empty script = nothing to do.
func (c Config) IsEmpty() bool {
	return c.SourceKind == "" && strings.TrimSpace(c.Script) == ""
}

// ReadFromPropertiesDir loads a Config from the property tree the
// pkg/properties subscriber maintains (typically /run/weft/properties).
// Each weft.boot/* property is a file ; missing files come back as
// empty strings (not an error — the host may have stamped only a
// subset).
func ReadFromPropertiesDir(root string) (Config, error) {
	c := Config{}
	for _, pair := range []struct {
		key string
		dst *string
	}{
		{"weft.boot/source.kind", &c.SourceKind},
		{"weft.boot/source.url", &c.SourceURL},
		{"weft.boot/source.ref", &c.SourceRef},
		{"weft.boot/script", &c.Script},
	} {
		v, err := readOptionalFile(filepath.Join(root, pair.key))
		if err != nil {
			return Config{}, err
		}
		*pair.dst = strings.TrimRight(v, "\n")
	}
	return c, nil
}

// readOptionalFile returns the file contents, or "" when the file
// doesn't exist. Other I/O errors propagate so the caller can decide
// (a transient disk error shouldn't silently look like "no script").
func readOptionalFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return string(b), nil
}

// Runner is the apply side : pull + script. WorkDir is the parent
// directory the payload lands under (.../payload subdir) ;
// SentinelPath is touched after a successful run so reboots skip.
// LogOut captures script stdout/stderr ; pass io.Discard if you
// don't care.
//
// Cloner is the git-clone hook ; nil means "git pull not supported"
// (the runner returns an error if SourceKind=="git" without a
// Cloner). Tests inject a stub ; production wires the os/exec
// helper in cmd/weft-vm-agent/boot_linux.go.
type Runner struct {
	WorkDir      string
	SentinelPath string
	LogOut       io.Writer
	Cloner       func(ctx context.Context, url, ref, dst string) error
}

// Run executes one provisioning pass. Idempotent : if SentinelPath
// already exists, returns nil immediately without touching anything.
// On success the sentinel is created ; on failure it isn't, so a
// re-published config can retry.
//
// Order of effects :
//
//  1. sentinel check  (early return when already provisioned)
//  2. pull            (git clone into <WorkDir>/payload ; skipped
//                     when SourceKind == "" or SourceKind == "oci"
//                     since OCI isn't wired yet)
//  3. script          (mvdan.cc/sh/v3 in payload CWD if it exists,
//                     else WorkDir)
//  4. sentinel write  (only when everything above succeeded)
func (r *Runner) Run(ctx context.Context, cfg Config) (err error) {
	if r.SentinelPath == "" {
		return errors.New("SentinelPath is required")
	}
	if r.LogOut == nil {
		r.LogOut = io.Discard
	}
	// 1. Sentinel : prior success → no-op.
	if _, statErr := os.Stat(r.SentinelPath); statErr == nil {
		fmt.Fprintln(r.LogOut, "weft-boot: sentinel present, skipping")
		return nil
	}

	if cfg.IsEmpty() {
		fmt.Fprintln(r.LogOut, "weft-boot: no provisioning requested ; stamping sentinel")
		return r.touchSentinel()
	}

	if err := os.MkdirAll(r.WorkDir, 0o755); err != nil {
		return fmt.Errorf("mkdir workdir: %w", err)
	}

	// 2. Pull.
	payloadDir := filepath.Join(r.WorkDir, "payload")
	switch cfg.SourceKind {
	case "", "none":
		// nothing to pull
	case "git":
		if r.Cloner == nil {
			return errors.New("git pull requested but no Cloner wired")
		}
		fmt.Fprintf(r.LogOut, "weft-boot: git clone %s @ %s -> %s\n", cfg.SourceURL, cfg.SourceRef, payloadDir)
		if err := r.Cloner(ctx, cfg.SourceURL, cfg.SourceRef, payloadDir); err != nil {
			return fmt.Errorf("git clone: %w", err)
		}
	case "oci":
		// Documented gap — see package doc. Returning a clear error
		// is better than silently dropping the source.
		return errors.New("oci provisioning not yet wired in this build (use git for now)")
	default:
		return fmt.Errorf("unknown source kind %q", cfg.SourceKind)
	}

	// 3. Script.
	if strings.TrimSpace(cfg.Script) != "" {
		cwd := r.WorkDir
		if _, statErr := os.Stat(payloadDir); statErr == nil {
			cwd = payloadDir
		}
		if err := RunScript(ctx, cfg.Script, cwd, r.LogOut); err != nil {
			return fmt.Errorf("script: %w", err)
		}
	}

	// 4. Sentinel.
	return r.touchSentinel()
}

func (r *Runner) touchSentinel() error {
	if err := os.MkdirAll(filepath.Dir(r.SentinelPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(r.SentinelPath, []byte("ok\n"), 0o644)
}

// RunScript parses + executes a POSIX sh body in cwd via
// mvdan.cc/sh/v3. Stdout + stderr go to logOut ; stdin is a closed
// empty reader (no interactive script). Errors from the interpreter
// (including non-zero exit) propagate.
//
// Exposed separately from Runner.Run so tests can exercise the
// script path without setting up a workdir / sentinel.
func RunScript(ctx context.Context, body, cwd string, logOut io.Writer) error {
	file, err := syntax.NewParser().Parse(strings.NewReader(body), "weft.boot/script")
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	runner, err := interp.New(
		interp.Dir(cwd),
		interp.StdIO(emptyReader{}, logOut, logOut),
	)
	if err != nil {
		return fmt.Errorf("new interp: %w", err)
	}
	return runner.Run(ctx, file)
}

// emptyReader is an always-EOF reader for the script's stdin.
// mvdan.cc/sh/v3 errors if StdIO's stdin is nil ; an explicit
// always-empty reader keeps the contract clean.
type emptyReader struct{}

func (emptyReader) Read(p []byte) (int, error) { return 0, io.EOF }

// Buffer is a small helper so callers can capture script output
// without depending on bytes.Buffer in tests. Wraps a bytes.Buffer
// so the returned writer is goroutine-safe enough for the runner's
// single-writer use.
type Buffer struct{ bytes.Buffer }
