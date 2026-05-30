// weft-microvm-agent runs inside an openweft micro-VM. It serves the read-only
// Introspect gRPC API (process table, …) to an operator CLI over the kernel
// WireGuard overlay (wg0), and — when pointed at the event bus — subscribes
// to mesh updates and re-applies its wg0 peer set whenever weft publishes a
// new desired state.
//
// The gRPC server uses insecure credentials: transport confidentiality is
// provided by wg0, like the rest of the platform's overlay-secured listeners.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/openweft/weft-microvm-init/pkg/pod"
	introspectv1 "github.com/openweft/weft-proto/introspectv1"
	"github.com/openweft/weft-microvm-agent/pkg/cubefs"
	"github.com/openweft/weft-microvm-agent/pkg/introspectsrv"
	agentmesh "github.com/openweft/weft-microvm-agent/pkg/mesh"
	agentboot "github.com/openweft/weft-microvm-agent/pkg/boot"
	agentmounts "github.com/openweft/weft-microvm-agent/pkg/mounts"
	agentproperties "github.com/openweft/weft-microvm-agent/pkg/properties"
	agentsshd "github.com/openweft/weft-microvm-agent/pkg/sshd"
	agentsshkeys "github.com/openweft/weft-microvm-agent/pkg/sshkeys"
	"google.golang.org/grpc"
)

func main() {
	listenAddr := flag.String("listen", "0.0.0.0:51999", "address to serve the Introspect API on (set to the VM's wg0 IP:port)")
	meshVMID := flag.String("mesh-vm-id", "", "this VM's id; when set, subscribe to mesh updates on the event bus")
	mountsVMID := flag.String("mounts-vm-id", "", "this VM's id; when set, subscribe to dynamic share-mount updates on the event bus")
	sshKeysVMID := flag.String("sshkeys-vm-id", "", "this VM's id; when set, subscribe to dynamic SSH-keys updates on the event bus")
	sshKeysAuthorizedKeys := flag.String("sshkeys-authorized-keys", "/root/.ssh/authorized_keys", "path to the authorized_keys file the sshkeys subscriber rewrites on each update")
	sshKeysUID := flag.Int("sshkeys-uid", 0, "uid to chown authorized_keys to (-1 to skip)")
	sshKeysGID := flag.Int("sshkeys-gid", 0, "gid to chown authorized_keys to (-1 to skip)")
	propsVMID := flag.String("properties-vm-id", "", "this VM's id; when set, subscribe to dynamic property updates on the event bus")
	propsDir := flag.String("properties-dir", "/run/weft/properties", "directory under which guest-readable properties are mirrored (file-per-key, nested on '/')")
	sshdListen := flag.String("sshd-listen", "", "address for the embedded SSH server (e.g. \"0.0.0.0:2222\" on the wg0 IP) ; empty disables it")
	sshdHostKey := flag.String("sshd-host-key", "/var/lib/weft/sshd_host_ed25519", "path to the persistent ed25519 host key for the embedded sshd (generated on first boot)")
	sshdShell := flag.String("sshd-shell", "/bin/sh", "shell binary execed on accepted sessions ; runs in the VM's PID-1 namespace, not the container's")
	bootWatch := flag.Bool("boot-watch", false, "watch the property tree for weft.boot/* and run first-boot provisioning once on appearance")
	bootWorkDir := flag.String("boot-workdir", "/var/lib/weft/boot", "parent directory for the boot payload ; <workdir>/payload is the git clone target + script CWD")
	bootSentinel := flag.String("boot-sentinel", "/var/lib/weft/provisioned", "sentinel file ; once present, boot provisioning is skipped (idempotent across reboots)")
	shareMounts := flag.String("share-mounts", "", "path to a JSON array of boot-time share mounts to apply at startup")
	natsURL := flag.String("nats-url", nats.DefaultURL, "event-bus URL for mesh/mount updates")
	natsCreds := flag.String("nats-creds", "", "path to NATS credentials (the per-project creds staged into the VM)")
	flag.Parse()

	logger := log.Default()

	// cfs-client ships in the initramfs at /bin/cfs-client (placed by the
	// runner via initbuild.PodInitrd); put /bin on $PATH so the mount
	// engine's PATH lookup of "cfs-client" resolves it — no embed/extract.
	os.Setenv("PATH", "/bin:/usr/bin:/sbin:"+os.Getenv("PATH"))

	// One registry backs both boot-time and dynamic share mounts, so a
	// dynamic unmount can target a boot-time mount by ID.
	reg := cubefs.NewRegistry()

	if *shareMounts != "" {
		if err := applyBootMounts(*shareMounts, reg, logger); err != nil {
			logger.Fatalf("weft-microvm-agent: share mounts: %v", err)
		}
	}

	if *meshVMID != "" {
		if err := startMesh(*natsURL, *natsCreds, *meshVMID, logger); err != nil {
			logger.Fatalf("weft-microvm-agent: mesh: %v", err)
		}
	}

	if *mountsVMID != "" {
		if err := startMounts(*natsURL, *natsCreds, *mountsVMID, reg, logger); err != nil {
			logger.Fatalf("weft-microvm-agent: mounts: %v", err)
		}
	}

	// Shared AuthStore : the sshkeys subscriber writes into it on
	// every NATS push ; the embedded sshd reads from it on every
	// connection. One source of truth for "which keys can SSH in
	// right now". Created unconditionally — cheap, harmless when
	// neither subscriber nor sshd are started.
	authStore := agentsshd.NewAuthStore()

	if *sshKeysVMID != "" {
		if err := startSSHKeys(*natsURL, *natsCreds, *sshKeysVMID,
			*sshKeysAuthorizedKeys, *sshKeysUID, *sshKeysGID, authStore, logger); err != nil {
			logger.Fatalf("weft-microvm-agent: sshkeys: %v", err)
		}
	}

	if *sshdListen != "" {
		if err := startSSHD(*sshdListen, *sshdHostKey, *sshdShell, authStore, logger); err != nil {
			logger.Fatalf("weft-microvm-agent: sshd: %v", err)
		}
	}

	// First-boot provisioning : watch the property tree for
	// weft.boot/* to appear, then run the configured payload + script
	// exactly once (sentinel-guarded). Disabled when --boot-watch
	// isn't set ; also a fast no-op when the sentinel already exists
	// (i.e. on subsequent reboots).
	if *bootWatch {
		runner := bootRunner(*bootWorkDir, *bootSentinel, logger.Writer())
		go watchAndRunBoot(*propsDir, runner, logger)
	}

	if *propsVMID != "" {
		if err := startProperties(*natsURL, *natsCreds, *propsVMID, *propsDir, logger); err != nil {
			logger.Fatalf("weft-microvm-agent: properties: %v", err)
		}
	}

	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		logger.Fatalf("weft-microvm-agent: listen %s: %v", *listenAddr, err)
	}

	srv := grpc.NewServer()
	introspectv1.RegisterIntrospectServer(srv, introspectsrv.New())

	logger.Printf("weft-microvm-agent: Introspect serving on %s", *listenAddr)
	if err := srv.Serve(lis); err != nil {
		logger.Fatalf("weft-microvm-agent: serve: %v", err)
	}
}

// startMesh connects to the event bus and subscribes to this VM's mesh
// updates, applying each via meshApply (kernel netlink on Linux).
func startMesh(url, creds, vmID string, logger *log.Logger) error {
	var opts []nats.Option
	if creds != "" {
		opts = append(opts, nats.UserCredentials(creds))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return err
	}
	sub := agentmesh.NewSubscriber(nc, vmID, meshApply, logger)
	if _, err := sub.Start(); err != nil {
		nc.Close()
		return err
	}
	logger.Printf("weft-microvm-agent: mesh subscribed on %s", agentmesh.Subject(vmID))
	return nil
}

// startMounts connects to the event bus and subscribes to this VM's
// dynamic share-mount updates, applying each via the shared registry
// (mount/unmount, replace-by-ID). This is what lets a teacher publish a
// share onto a class of student VMs at runtime.
func startMounts(url, creds, vmID string, reg *cubefs.Registry, logger *log.Logger) error {
	var opts []nats.Option
	if creds != "" {
		opts = append(opts, nats.UserCredentials(creds))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return err
	}
	sub := agentmounts.NewSubscriber(nc, vmID, reg.Apply, logger)
	if _, err := sub.Start(); err != nil {
		nc.Close()
		return err
	}
	logger.Printf("weft-microvm-agent: mounts subscribed on %s", agentmounts.Subject(vmID))
	return nil
}

// startSSHKeys connects to the event bus and subscribes to this VM's
// SSH-keys updates. Two effects on each push :
//  1. Rewrite the target user's authorized_keys atomically (keeps a
//     workload-side sshd, if any, functional).
//  2. Replace the AuthStore consulted by the embedded sshd in pkg/sshd.
//
// Same Subscriber+ApplyFunc pattern as mesh / mounts — state is whole,
// not diffed, so a missed message self-heals on the next publish (an
// empty set is a valid "revoke all" state and is also applied).
//
// authStore may be nil if the embedded sshd is disabled ; the
// authorized_keys writer still runs for backward compat.
func startSSHKeys(url, creds, vmID, authorizedKeysPath string, uid, gid int, authStore *agentsshd.AuthStore, logger *log.Logger) error {
	var opts []nats.Option
	if creds != "" {
		opts = append(opts, nats.UserCredentials(creds))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return err
	}
	// Compose the apply : both writes happen, both errors are
	// surfaced. The authStore replace is cheap + memory-only ; the
	// authorized_keys path may fail (read-only fs in tests, for
	// instance) but that shouldn't block the authstore update.
	fileApply := sshKeysApplyer(authorizedKeysPath, uid, gid)
	composed := func(ks agentsshkeys.KeySet) error {
		if authStore != nil {
			accepted, rejected := authStore.Replace(ks)
			logger.Printf("weft-microvm-agent: sshkeys authstore : %d accepted, %d rejected", accepted, rejected)
		}
		return fileApply(ks)
	}
	sub := agentsshkeys.NewSubscriber(nc, vmID, composed, logger)
	if _, err := sub.Start(); err != nil {
		nc.Close()
		return err
	}
	logger.Printf("weft-microvm-agent: sshkeys subscribed on %s -> authorized_keys=%s + AuthStore", agentsshkeys.Subject(vmID), authorizedKeysPath)
	return nil
}

// startSSHD wires the embedded SSH server : loads (or generates) the
// persistent host key, builds the server with the shared AuthStore,
// binds the listener, and serves in a goroutine. Failures during
// listener binding are fatal (returned to caller) ; per-connection
// errors are logged + dropped.
func startSSHD(listen, hostKeyPath, shell string, authStore *agentsshd.AuthStore, logger *log.Logger) error {
	signer, err := agentsshd.LoadOrCreateHostKey(hostKeyPath)
	if err != nil {
		return fmt.Errorf("host key %s: %w", hostKeyPath, err)
	}
	srv, err := agentsshd.NewServer(authStore, signer, shell, logger)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listen, err)
	}
	logger.Printf("weft-microvm-agent: sshd on %s (host key %s)", ln.Addr(), hostKeyPath)
	go func() {
		if err := srv.Serve(ln); err != nil {
			logger.Printf("weft-microvm-agent: sshd serve: %v", err)
		}
	}()
	return nil
}

// startProperties connects to the event bus and subscribes to this
// VM's property updates, mirroring the desired set onto a POSIX tree
// (file-per-key, "/" → directory nesting). Any in-VM process reads
// via `cat <propertiesDir>/<key>`. Replace-set semantics : an empty
// publish clears the tree, missed messages self-heal on next publish.
func startProperties(url, creds, vmID, propertiesDir string, logger *log.Logger) error {
	var opts []nats.Option
	if creds != "" {
		opts = append(opts, nats.UserCredentials(creds))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return err
	}
	sub := agentproperties.NewSubscriber(nc, vmID, propertiesApplyer(propertiesDir), logger)
	if _, err := sub.Start(); err != nil {
		nc.Close()
		return err
	}
	logger.Printf("weft-microvm-agent: properties subscribed on %s -> %s", agentproperties.Subject(vmID), propertiesDir)
	return nil
}

// watchAndRunBoot polls the property tree for weft.boot/* and runs
// the boot.Runner once the request lands. Polling (not inotify) :
// pkg/properties writes via tmp+rename which inotify would catch
// cleanly, but the polling loop is ~10 lines + zero deps, and the
// max latency is the poll interval. Idempotent : the Runner's
// sentinel check short-circuits on subsequent reboots.
//
// Bails after maxWait without a request — the operator may have
// stamped no boot config, in which case the sentinel is written
// anyway so future polls return immediately.
func watchAndRunBoot(propsDir string, runner *agentboot.Runner, logger *log.Logger) {
	const (
		pollEvery = 2 * time.Second
		maxWait   = 5 * time.Minute
	)
	ctx, cancel := context.WithTimeout(context.Background(), maxWait+30*time.Second)
	defer cancel()

	deadline := time.Now().Add(maxWait)
	for {
		// Sentinel already there ? Subsequent reboot ; nothing to do.
		if _, err := os.Stat(runner.SentinelPath); err == nil {
			logger.Printf("weft-microvm-agent: boot sentinel present, skipping")
			return
		}

		cfg, err := agentboot.ReadFromPropertiesDir(propsDir)
		if err != nil {
			logger.Printf("weft-microvm-agent: boot read %s: %v", propsDir, err)
			time.Sleep(pollEvery)
			continue
		}

		// Wait until SOMETHING is set OR we time out. Running with an
		// all-empty config too early would stamp the sentinel before
		// the host had a chance to publish.
		if !cfg.IsEmpty() {
			logger.Printf("weft-microvm-agent: boot config seen ; provisioning (kind=%q url=%q script-bytes=%d)",
				cfg.SourceKind, cfg.SourceURL, len(cfg.Script))
			if err := runner.Run(ctx, cfg); err != nil {
				logger.Printf("weft-microvm-agent: boot run: %v", err)
				return
			}
			logger.Printf("weft-microvm-agent: boot run ok ; sentinel written")
			return
		}

		if time.Now().After(deadline) {
			logger.Printf("weft-microvm-agent: boot : no config after %s, stamping sentinel + exiting watcher", maxWait)
			_ = runner.Run(ctx, agentboot.Config{}) // empty Run stamps the sentinel
			return
		}
		time.Sleep(pollEvery)
	}
}

// applyBootMounts applies the static share mounts listed in a JSON file at
// startup (the host drops it into the config share). Failures are fatal —
// a workload that expects its data share present shouldn't start without it.
func applyBootMounts(path string, reg *cubefs.Registry, logger *log.Logger) error {
	mounts, err := pod.LoadShareMounts(path)
	if err != nil {
		return err
	}
	for _, m := range mounts {
		if err := reg.Apply(m); err != nil {
			return fmt.Errorf("apply %q: %w", m.ID, err)
		}
		logger.Printf("weft-microvm-agent: mounted %s at %s", m.ID, m.MountPoint)
	}
	return nil
}
