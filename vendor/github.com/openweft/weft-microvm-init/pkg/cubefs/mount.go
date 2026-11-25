package cubefs

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/openweft/weft-microvm-init/pkg/pod"
	"github.com/openweft/weft-microvm-init/pkg/secretclient"
)

// runRoot is where per-mount cfs-client config + logs live.
var runRoot = "/run/weft/cubefs"

// Mounted is a live CubeFS mount: the cfs-client process plus its mount
// point. Unmount detaches the FUSE mount and stops the client.
type Mounted struct {
	mountPoint string
	cmd        *exec.Cmd
	logf       *os.File      // owned; closed on Unmount
	exited     chan struct{} // closed by the reaper goroutine once cmd has exited

	secretVersion uint64 // CubeFSMount.SecretVersion the mount was made with
}

// SecretVersion reports the secret_version the mount was made with.
func (m *Mounted) SecretVersion() uint64 { return m.secretVersion }

// MountPoint reports where the share is mounted in the guest.
func (m *Mounted) MountPoint() string { return m.mountPoint }

// Unmount detaches the FUSE mount then stops cfs-client. Best-effort: the
// kernel mount is removed even if stopping the process errs. Waits for the
// reaper goroutine so the process is fully reaped before the log file is
// closed.
func (m *Mounted) Unmount() error {
	uerr := unmountPath(m.mountPoint)
	if m.cmd != nil && m.cmd.Process != nil {
		// Kill is harmless (ESRCH, ignored) if the reaper already saw
		// cfs-client die on its own — e.g. because fusermount detached the
		// mount above and cfs-client exited.
		_ = m.cmd.Process.Kill()
	}
	if m.exited != nil {
		<-m.exited
	}
	if m.logf != nil {
		_ = m.logf.Close()
		m.logf = nil
	}
	return uerr
}

// Mount attaches the CubeFS volume described by spec at spec.MountPoint by
// launching cfs-client, and returns once the mount is live. spec must
// already be Validate()d by the caller.
func Mount(spec pod.ShareMount) (*Mounted, error) {
	if spec.EffectiveBackend() != pod.BackendCubeFS {
		return nil, fmt.Errorf("cubefs: unsupported backend %q", spec.EffectiveBackend())
	}
	if err := os.MkdirAll(spec.MountPoint, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir mount point %s: %w", spec.MountPoint, err)
	}
	runDir := filepath.Join(runRoot, spec.ID)
	logDir := filepath.Join(runDir, "log")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir run dir %s: %w", runDir, err)
	}
	cfg, err := clientConfig(spec, logDir)
	if err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(runDir, "config.json")
	err = os.WriteFile(cfgPath, cfg, 0o600)
	clear(cfg) // the rendered config holds the keys
	if err != nil {
		return nil, fmt.Errorf("write cfs-client config: %w", err)
	}

	// -f keeps cfs-client in the foreground so we own the process and can
	// stop it on unmount, rather than it daemonising away.
	cmd := exec.Command(Binary, "-f", "-c", cfgPath)
	logf, _ := os.Create(filepath.Join(logDir, "cfs-client.out"))
	if logf != nil {
		cmd.Stdout = logf
		cmd.Stderr = logf
	}
	if err := cmd.Start(); err != nil {
		if logf != nil {
			_ = logf.Close()
		}
		return nil, fmt.Errorf("start cfs-client: %w", err)
	}
	// Reaper: ensures cfs-client never becomes a zombie if it exits on its
	// own (network drop, OOM, misconfig) before Unmount is called.
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	if err := waitMounted(spec.MountPoint, 30*time.Second); err != nil {
		_ = cmd.Process.Kill()
		<-exited
		if logf != nil {
			_ = logf.Close()
		}
		return nil, fmt.Errorf("cubefs %q: %w", spec.ID, err)
	}
	return &Mounted{mountPoint: spec.MountPoint, cmd: cmd, logf: logf, exited: exited,
		secretVersion: spec.CubeFS.SecretVersion}, nil
}

// waitMounted polls /proc/mounts until target appears as a mount or the
// timeout elapses.
func waitMounted(target string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if isMounted(target) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("mount %s did not appear within %s", target, timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// isMounted reports whether target is a mount point, per /proc/mounts.
func isMounted(target string) bool {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[1] == target {
			return true
		}
	}
	return false
}

// unmountPath detaches a FUSE mount. Tries fusermount3/fusermount (the
// unprivileged FUSE path) then falls back to umount.
func unmountPath(target string) error {
	for _, c := range [][]string{
		{"fusermount3", "-u", target},
		{"fusermount", "-u", target},
		{"umount", target},
	} {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		if err := exec.Command(c[0], c[1:]...).Run(); err == nil {
			return nil
		}
	}
	return fmt.Errorf("could not unmount %s (no working fusermount/umount)", target)
}

// Registry tracks live mounts by ShareMount.ID so dynamic updates can
// replace-by-ID or unmount idempotently. Safe for concurrent use by the
// event-bus apply callback.
type Registry struct {
	mu      sync.Mutex
	active  map[string]*Mounted
	secrets secretclient.Source
	mount   func(pod.ShareMount) (*Mounted, error) // Mount; a test seam
}

// NewRegistry returns a Registry with no secret source: a mount that names a
// *_ref is refused. Use NewRegistryWithSecrets to resolve them.
func NewRegistry() *Registry { return NewRegistryWithSecrets(nil) }

// NewRegistryWithSecrets returns a Registry that resolves *_ref keys from src
// (the vsock GuestSecrets client in production).
func NewRegistryWithSecrets(src secretclient.Source) *Registry {
	return &Registry{active: map[string]*Mounted{}, secrets: src, mount: Mount}
}

// Apply reconciles one ShareMount against the registry: unmount on the
// unmount action, otherwise (re)mount, replacing any existing mount with
// the same ID. Idempotent — a repeated publish re-establishes the mount.
//
// Keys named by *_ref are fetched over vsock BEFORE the existing mount is
// touched, so a failed fetch leaves the old mount up. Rotation is a message
// with a new secret_version: the remount here fetches the current value.
func (r *Registry) Apply(spec pod.ShareMount) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if spec.Action != pod.MountActionUnmount {
		resolved, wipe, err := Resolve(context.Background(), spec, r.secrets)
		if err != nil {
			return err
		}
		defer wipe()
		spec = resolved
	}
	if existing := r.active[spec.ID]; existing != nil {
		if err := existing.Unmount(); err != nil {
			return err
		}
		delete(r.active, spec.ID)
	}
	if spec.Action == pod.MountActionUnmount {
		return nil
	}
	m, err := r.mount(spec)
	if err != nil {
		return err
	}
	r.active[spec.ID] = m
	return nil
}

// UnmountAll tears down every live mount (best-effort; returns the first
// error). Call on agent shutdown.
func (r *Registry) UnmountAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var first error
	for id, m := range r.active {
		if err := m.Unmount(); err != nil && first == nil {
			first = err
		}
		delete(r.active, id)
	}
	return first
}
