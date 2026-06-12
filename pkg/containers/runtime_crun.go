//go:build linux

package containers

// runtime_crun.go — production Runtime backed by crun. Pulls images
// via ncl (or skips when the image is pre-baked in the rootfs),
// renders a minimal OCI runtime-spec config.json from
// pod.WorkloadContainer, then drives `crun create` + `crun start`.
//
// Linux-only by build tag : the agent only ever runs on Linux guests.
// host-side `go build` of loom-server pulls runtime_stub.go instead.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// CrunRuntime drives crun. BundleRoot is where per-container bundle
// dirs land (<bundleRoot>/<name>/{config.json,rootfs}) ; NCLImagePath
// is the ncl cache the pre-baked rootfs lives under when an image
// has already been pre-staged at build time (the dev path).
type CrunRuntime struct {
	BundleRoot   string // e.g. "/run/weft/containers"
	NCLImagePath string // e.g. "/run/weft/images"
	Logger       *log.Logger
}

// Pull defers to ncl to fetch+unpack the image. When ncl isn't on
// PATH (dev rootfs without ncl pre-baked) the pull is treated as a
// no-op : Start will look for a pre-staged rootfs at NCLImagePath
// keyed by image ref and use that. Lets the dev path work today
// without the full V0.6 ncl pipeline in place.
func (r *CrunRuntime) Pull(ctx context.Context, image string) error {
	if _, err := exec.LookPath("ncl"); err != nil {
		if r.Logger != nil {
			r.Logger.Printf("crun pull image=%s : ncl not on PATH, assuming pre-staged rootfs", image)
		}
		return nil
	}
	cmd := exec.CommandContext(ctx, "ncl", "pull", "--cache", r.NCLImagePath, image)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// Start materialises an OCI bundle from the pulled image + asks crun
// to run it. The bundle lives at <BundleRoot>/<name>/ with config.json
// rendered from c (Command/Args/Env/Mounts/WorkingDir/Net) and
// rootfs symlinked / bind-mounted from the ncl image cache.
//
// Restart="always" is honoured by the agent's reconciler layer (it
// re-invokes Start on exit) ; this method is fire-and-forget once
// crun start returns.
func (r *CrunRuntime) Start(ctx context.Context, c pod.WorkloadContainer) error {
	bundle := filepath.Join(r.BundleRoot, c.Name)
	rootfsDir := filepath.Join(bundle, "rootfs")
	if err := os.MkdirAll(rootfsDir, 0o755); err != nil {
		return fmt.Errorf("mkdir bundle %s: %w", bundle, err)
	}

	// Resolve the rootfs : ncl's unpack path keyed by image ref-safe
	// dir (`/` and `:` swapped for `-` to land in a single directory
	// level). When the directory has content we bind-mount it ; when
	// empty (no ncl pull ever happened) we fall through to use the
	// agent's own rootfs as a stub so `crun exec` against a known
	// host-side binary still works in the dev path.
	refSafe := strings.NewReplacer("/", "-", ":", "-", "@", "-").Replace(c.Image)
	src := filepath.Join(r.NCLImagePath, refSafe, "rootfs")
	if info, err := os.Stat(src); err != nil || !info.IsDir() {
		// dev path : the image isn't pre-staged. Use `/` so the
		// container sees the agent's own rootfs. The agent's
		// /workspace 9p mount carries through, and tooling that
		// happens to be in the rootfs is invocable. Real prod path
		// is ncl pull → rootfs unpack into NCLImagePath.
		src = "/"
		if r.Logger != nil {
			r.Logger.Printf("crun start name=%s : no rootfs at %s, falling back to agent rootfs (dev path)", c.Name, src)
		}
	}

	// Render OCI config.json. Minimum viable spec : process, root,
	// mounts (proc + sys + /workspace passthrough), linux namespaces.
	spec := map[string]any{
		"ociVersion": "1.0.2",
		"process": map[string]any{
			"terminal": false,
			"user":     map[string]any{"uid": 0, "gid": 0},
			"args":     argv(c),
			"env":      env(c),
			"cwd":      cwd(c),
			"capabilities": map[string]any{
				"bounding":  []string{"CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"},
				"effective": []string{"CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"},
				"permitted": []string{"CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"},
			},
			"noNewPrivileges": true,
		},
		"root": map[string]any{
			"path":     src,
			"readonly": false,
		},
		"hostname": c.Name,
		"mounts": []map[string]any{
			{"destination": "/proc", "type": "proc", "source": "proc"},
			{"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": []string{"nosuid", "noexec", "nodev", "ro"}},
			{"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
			{"destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}},
		},
		"linux": map[string]any{
			"namespaces": linuxNamespaces(c),
		},
	}
	// Append the user's mounts (typically /workspace bind from host).
	mounts := spec["mounts"].([]map[string]any)
	for _, m := range c.Mounts {
		options := []string{"bind", "rprivate"}
		if m.Readonly {
			options = append(options, "ro")
		} else {
			options = append(options, "rw")
		}
		mounts = append(mounts, map[string]any{
			"destination": m.MountPath,
			"type":        "bind",
			"source":      m.HostPath,
			"options":     options,
		})
	}
	spec["mounts"] = mounts

	configBytes, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), configBytes, 0o644); err != nil {
		return fmt.Errorf("write config.json: %w", err)
	}

	cmd := exec.CommandContext(ctx, "crun", "run", "--detach",
		"--bundle", bundle, c.Name)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("crun run %s: %w", c.Name, err)
	}
	if r.Logger != nil {
		r.Logger.Printf("crun start name=%s image=%s bundle=%s", c.Name, c.Image, bundle)
	}
	return nil
}

// argv computes the container's process argv : Command + Args. Falls
// back to a shell loop so a container with no command set stays
// long-running (the tool-wrapper pattern needs the container warm).
func argv(c pod.WorkloadContainer) []string {
	if len(c.Command) == 0 {
		// Sleep-forever entrypoint : `crun exec` against this
		// container is how tool wrappers invoke the real binaries.
		return []string{"/bin/sh", "-c", "while true; do sleep 3600; done"}
	}
	return append(append([]string{}, c.Command...), c.Args...)
}

func env(c pod.WorkloadContainer) []string {
	out := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root",
		"TERM=xterm",
	}
	for k, v := range c.Env {
		out = append(out, k+"="+v)
	}
	return out
}

func cwd(c pod.WorkloadContainer) string {
	if c.WorkingDir != "" {
		return c.WorkingDir
	}
	return "/workspace"
}

// linuxNamespaces : standard isolation set. Net = host (shares the
// guest's net namespace) when c.Net == "host", else its own.
func linuxNamespaces(c pod.WorkloadContainer) []map[string]any {
	out := []map[string]any{
		{"type": "pid"},
		{"type": "mount"},
		{"type": "ipc"},
		{"type": "uts"},
	}
	if c.Net != "host" {
		out = append(out, map[string]any{"type": "network"})
	}
	return out
}

// Stop terminates the container + reaps the bundle dir.
func (r *CrunRuntime) Stop(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, "crun", "kill", name, "SIGTERM")
	if err := cmd.Run(); err != nil {
		if r.Logger != nil {
			r.Logger.Printf("crun kill %s: %v (continuing)", name, err)
		}
	}
	// Best-effort delete to clean state. Tolerate "container does
	// not exist" — crun kill above may have already cleaned up.
	_ = exec.CommandContext(ctx, "crun", "delete", "-f", name).Run()
	_ = os.RemoveAll(filepath.Join(r.BundleRoot, name))
	return nil
}

// Running asks crun for the list of containers it knows about.
func (r *CrunRuntime) Running(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, "crun", "list", "-q")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var names []string
	start := 0
	for i, b := range out {
		if b == '\n' {
			if start < i {
				names = append(names, string(out[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(out) {
		names = append(names, string(out[start:]))
	}
	return names, nil
}
