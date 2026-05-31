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
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/openweft/weft-microvm-agent/internal/metrics"
	agentboot "github.com/openweft/weft-microvm-agent/pkg/boot"
	"github.com/openweft/weft-microvm-agent/pkg/cubefs"
	"github.com/openweft/weft-microvm-agent/pkg/introspectsrv"
	agentmesh "github.com/openweft/weft-microvm-agent/pkg/mesh"
	agentmounts "github.com/openweft/weft-microvm-agent/pkg/mounts"
	agentproperties "github.com/openweft/weft-microvm-agent/pkg/properties"
	agentsshd "github.com/openweft/weft-microvm-agent/pkg/sshd"
	agentsshkeys "github.com/openweft/weft-microvm-agent/pkg/sshkeys"
	"github.com/openweft/weft-microvm-init/pkg/pod"
	introspectv1 "github.com/openweft/weft-proto/introspectv1"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

// Build-time stamps populated via -ldflags "-X main.version=…".
// The metrics package surfaces these as labels on the
// weft_microvm_agent_build_info gauge so a multi-VM scrape can tell
// which binary is running where.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// opts is the agent's runtime config. Cobra binds every flag onto one of
// these fields so the RunE handler is a pure run(opts) — no globals, no
// pointer-deref, easy to feed from tests too.
type opts struct {
	listenAddr            string
	meshVMID              string
	mountsVMID            string
	sshKeysVMID           string
	sshKeysAuthorizedKeys string
	sshKeysUID            int
	sshKeysGID            int
	propsVMID             string
	propsDir              string
	sshdListen            string
	sshdHostKey           string
	sshdShell             string
	bootWatch             bool
	bootWorkDir           string
	bootSentinel          string
	shareMounts           string
	natsURL               string
	natsCreds             string
	metricsAddr           string
}

func main() {
	var o opts
	cmd := &cobra.Command{
		Use:   "weft-microvm-agent",
		Short: "Guest-side agent for openweft microVMs (Introspect gRPC over wg0 + NATS-driven dynamic config)",
		Long: `weft-microvm-agent runs as a long-lived in-guest service inside an openweft
microVM. It exposes the read-only Introspect gRPC API to an operator over the
kernel WireGuard overlay (wg0) and, when given a per-VM id and a NATS URL,
subscribes to mesh / share-mount / SSH-keys / property updates and applies
them idempotently with replace-by-ID semantics.

All transports rely on wg0 for confidentiality; the gRPC server itself uses
insecure credentials.`,
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return run(o)
		},
	}

	f := cmd.Flags()
	f.StringVar(&o.listenAddr, "listen", "0.0.0.0:51999", "address to serve the Introspect API on (set to the VM's wg0 IP:port)")
	f.StringVar(&o.meshVMID, "mesh-vm-id", "", "this VM's id; when set, subscribe to mesh updates on the event bus")
	f.StringVar(&o.mountsVMID, "mounts-vm-id", "", "this VM's id; when set, subscribe to dynamic share-mount updates on the event bus")
	f.StringVar(&o.sshKeysVMID, "sshkeys-vm-id", "", "this VM's id; when set, subscribe to dynamic SSH-keys updates on the event bus")
	f.StringVar(&o.sshKeysAuthorizedKeys, "sshkeys-authorized-keys", "/root/.ssh/authorized_keys", "authorized_keys file the sshkeys subscriber rewrites on each update")
	f.IntVar(&o.sshKeysUID, "sshkeys-uid", 0, "uid to chown authorized_keys to (-1 to skip)")
	f.IntVar(&o.sshKeysGID, "sshkeys-gid", 0, "gid to chown authorized_keys to (-1 to skip)")
	f.StringVar(&o.propsVMID, "properties-vm-id", "", "this VM's id; when set, subscribe to dynamic property updates on the event bus")
	f.StringVar(&o.propsDir, "properties-dir", "/run/weft/properties", "directory under which guest-readable properties are mirrored (file-per-key, nested on '/')")
	f.StringVar(&o.sshdListen, "sshd-listen", "", `address for the embedded SSH server (e.g. "0.0.0.0:2222" on the wg0 IP); empty disables it`)
	f.StringVar(&o.sshdHostKey, "sshd-host-key", "/var/lib/weft/sshd_host_ed25519", "persistent ed25519 host key for the embedded sshd (generated on first boot)")
	f.StringVar(&o.sshdShell, "sshd-shell", "/bin/sh", "shell binary execed on accepted sessions; runs in the VM's PID-1 namespace, not the container's")
	f.BoolVar(&o.bootWatch, "boot-watch", false, "watch the property tree for weft.boot/* and run first-boot provisioning once on appearance")
	f.StringVar(&o.bootWorkDir, "boot-workdir", "/var/lib/weft/boot", "parent directory for the boot payload; <workdir>/payload is the git clone target + script CWD")
	f.StringVar(&o.bootSentinel, "boot-sentinel", "/var/lib/weft/provisioned", "sentinel file; once present, boot provisioning is skipped (idempotent across reboots)")
	f.StringVar(&o.shareMounts, "share-mounts", "", "path to a JSON array of boot-time share mounts to apply at startup")
	f.StringVar(&o.natsURL, "nats-url", nats.DefaultURL, "event-bus URL for mesh/mount updates")
	f.StringVar(&o.natsCreds, "nats-creds", "", "path to NATS credentials (the per-project creds staged into the VM)")
	// Distinct port from weft-network's :9100 so a host that ever
	// finds both daemons sharing a lo (e.g. an agent VM with a
	// co-located network shim) doesn't see a port collision.
	f.StringVar(&o.metricsAddr, "metrics-addr", ":9101", "Prometheus /metrics + /healthz listen address ; empty disables. tcp:host:port shape.")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// run is the daemon body. It returns an error so cobra can surface it
// without forcing the helpers below to call log.Fatal. The final
// gRPC Serve call blocks; an early exit before it means a setup error.
func run(o opts) error {
	logger := log.Default()

	// cfs-client ships in the initramfs at /bin/cfs-client (placed by the
	// runner via initbuild.PodInitrd); put /bin on $PATH so the mount
	// engine's PATH lookup of "cfs-client" resolves it — no embed/extract.
	os.Setenv("PATH", "/bin:/usr/bin:/sbin:"+os.Getenv("PATH"))

	// Prometheus recorder is built unconditionally so even a no-NATS
	// agent (Introspect-only mode) still exposes build_info and a
	// /healthz the supervisor can poll. SetNATSConnected flips only
	// when a subscriber successfully dials.
	rec := metrics.New(version, commit, date)
	logger.Printf("weft-microvm-agent: build version=%s commit=%s date=%s", version, commit, date)

	// One registry backs both boot-time and dynamic share mounts, so a
	// dynamic unmount can target a boot-time mount by ID.
	reg := cubefs.NewRegistry()

	if o.shareMounts != "" {
		if err := applyBootMounts(o.shareMounts, reg, logger); err != nil {
			return fmt.Errorf("share mounts: %w", err)
		}
	}

	if o.meshVMID != "" {
		if err := startMesh(o.natsURL, o.natsCreds, o.meshVMID, rec, logger); err != nil {
			return fmt.Errorf("mesh: %w", err)
		}
	}

	if o.mountsVMID != "" {
		if err := startMounts(o.natsURL, o.natsCreds, o.mountsVMID, reg, rec, logger); err != nil {
			return fmt.Errorf("mounts: %w", err)
		}
	}

	// Shared AuthStore: the sshkeys subscriber writes into it on every NATS
	// push; the embedded sshd reads from it on every connection. One source
	// of truth for "which keys can SSH in right now". Created unconditionally
	// — cheap, harmless when neither subscriber nor sshd are started.
	authStore := agentsshd.NewAuthStore()

	if o.sshKeysVMID != "" {
		if err := startSSHKeys(o.natsURL, o.natsCreds, o.sshKeysVMID,
			o.sshKeysAuthorizedKeys, o.sshKeysUID, o.sshKeysGID, authStore, rec, logger); err != nil {
			return fmt.Errorf("sshkeys: %w", err)
		}
	}

	if o.sshdListen != "" {
		if err := startSSHD(o.sshdListen, o.sshdHostKey, o.sshdShell, authStore, logger); err != nil {
			return fmt.Errorf("sshd: %w", err)
		}
	}

	// First-boot provisioning: watch the property tree for weft.boot/* to
	// appear, then run the configured payload + script exactly once
	// (sentinel-guarded). Disabled when --boot-watch isn't set; also a fast
	// no-op when the sentinel already exists (subsequent reboots).
	if o.bootWatch {
		runner := bootRunner(o.bootWorkDir, o.bootSentinel, logger.Writer())
		go watchAndRunBoot(o.propsDir, runner, rec, logger)
	}

	if o.propsVMID != "" {
		if err := startProperties(o.natsURL, o.natsCreds, o.propsVMID, o.propsDir, rec, logger); err != nil {
			return fmt.Errorf("properties: %w", err)
		}
	}

	lis, err := net.Listen("tcp", o.listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", o.listenAddr, err)
	}

	srv := grpc.NewServer()
	introspectv1.RegisterIntrospectServer(srv, introspectsrv.New())

	// /metrics + /healthz on a dedicated listener — separate fate from
	// the Introspect gRPC so a scrape-side hang can't take down the
	// control surface. Disabled when --metrics-addr is empty.
	var metricsSrv *http.Server
	if o.metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", rec.Handler())
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		})
		metricsSrv = &http.Server{
			Addr:              o.metricsAddr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			logger.Printf("weft-microvm-agent: metrics listener on %s", o.metricsAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Printf("weft-microvm-agent: metrics serve: %v", err)
			}
		}()
	}

	// Cooperative shutdown : SIGINT / SIGTERM triggers GracefulStop on
	// gRPC so in-flight Introspect calls finish before exit. The
	// metrics HTTP listener shuts down in parallel ; the 5s bound is
	// plenty for an idle scrape connection to drain.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		logger.Printf("weft-microvm-agent: signal received ; graceful stop")
		if metricsSrv != nil {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = metricsSrv.Shutdown(shutCtx)
		}
		srv.GracefulStop()
	}()

	logger.Printf("weft-microvm-agent: Introspect serving on %s", o.listenAddr)
	if err := srv.Serve(lis); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// startMesh connects to the event bus and subscribes to this VM's mesh
// updates, applying each via meshApply (kernel netlink on Linux). The
// recorded apply is wrapped around the production ApplyFunc so every
// mesh update lands in weft_microvm_agent_apply_total{concern="mesh"}.
func startMesh(url, creds, vmID string, rec *metrics.Recorder, logger *log.Logger) error {
	var opts []nats.Option
	if creds != "" {
		opts = append(opts, nats.UserCredentials(creds))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return err
	}
	rec.SetNATSConnected(true)
	apply := func(wg *pod.WireGuard) error {
		start := time.Now()
		err := meshApply(wg)
		rec.RecordApply("mesh", err, time.Since(start))
		return err
	}
	sub := agentmesh.NewSubscriber(nc, vmID, apply, logger)
	if _, err := sub.Start(); err != nil {
		nc.Close()
		rec.SetNATSConnected(false)
		return err
	}
	logger.Printf("weft-microvm-agent: mesh subscribed on %s", agentmesh.Subject(vmID))
	return nil
}

// startMounts connects to the event bus and subscribes to this VM's
// dynamic share-mount updates, applying each via the shared registry
// (mount/unmount, replace-by-ID). This is what lets a teacher publish a
// share onto a class of student VMs at runtime.
func startMounts(url, creds, vmID string, reg *cubefs.Registry, rec *metrics.Recorder, logger *log.Logger) error {
	var opts []nats.Option
	if creds != "" {
		opts = append(opts, nats.UserCredentials(creds))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return err
	}
	rec.SetNATSConnected(true)
	apply := func(m pod.ShareMount) error {
		start := time.Now()
		err := reg.Apply(m)
		rec.RecordApply("mounts", err, time.Since(start))
		return err
	}
	sub := agentmounts.NewSubscriber(nc, vmID, apply, logger)
	if _, err := sub.Start(); err != nil {
		nc.Close()
		rec.SetNATSConnected(false)
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
// authStore may be nil if the embedded sshd is disabled; the
// authorized_keys writer still runs for backward compat.
func startSSHKeys(url, creds, vmID, authorizedKeysPath string, uid, gid int, authStore *agentsshd.AuthStore, rec *metrics.Recorder, logger *log.Logger) error {
	var opts []nats.Option
	if creds != "" {
		opts = append(opts, nats.UserCredentials(creds))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return err
	}
	rec.SetNATSConnected(true)
	// Compose the apply: both writes happen, both errors are surfaced. The
	// authStore replace is cheap + memory-only; the authorized_keys path
	// may fail (read-only fs in tests, for instance) but that shouldn't
	// block the authstore update.
	fileApply := sshKeysApplyer(authorizedKeysPath, uid, gid)
	composed := func(ks agentsshkeys.KeySet) error {
		start := time.Now()
		if authStore != nil {
			accepted, rejected := authStore.Replace(ks)
			logger.Printf("weft-microvm-agent: sshkeys authstore : %d accepted, %d rejected", accepted, rejected)
		}
		err := fileApply(ks)
		rec.RecordApply("sshkeys", err, time.Since(start))
		return err
	}
	sub := agentsshkeys.NewSubscriber(nc, vmID, composed, logger)
	if _, err := sub.Start(); err != nil {
		nc.Close()
		rec.SetNATSConnected(false)
		return err
	}
	logger.Printf("weft-microvm-agent: sshkeys subscribed on %s -> authorized_keys=%s + AuthStore", agentsshkeys.Subject(vmID), authorizedKeysPath)
	return nil
}

// startSSHD wires the embedded SSH server: loads (or generates) the
// persistent host key, builds the server with the shared AuthStore,
// binds the listener, and serves in a goroutine. Failures during
// listener binding are fatal (returned to caller); per-connection
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

// startProperties connects to the event bus and subscribes to this VM's
// property updates, mirroring the desired set onto a POSIX tree
// (file-per-key, "/" → directory nesting). Any in-VM process reads via
// `cat <propertiesDir>/<key>`. Replace-set semantics: an empty publish
// clears the tree, missed messages self-heal on next publish.
func startProperties(url, creds, vmID, propertiesDir string, rec *metrics.Recorder, logger *log.Logger) error {
	var opts []nats.Option
	if creds != "" {
		opts = append(opts, nats.UserCredentials(creds))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return err
	}
	rec.SetNATSConnected(true)
	inner := propertiesApplyer(propertiesDir)
	apply := func(ps agentproperties.PropertySet) error {
		start := time.Now()
		err := inner(ps)
		rec.RecordApply("properties", err, time.Since(start))
		return err
	}
	sub := agentproperties.NewSubscriber(nc, vmID, apply, logger)
	if _, err := sub.Start(); err != nil {
		nc.Close()
		rec.SetNATSConnected(false)
		return err
	}
	logger.Printf("weft-microvm-agent: properties subscribed on %s -> %s", agentproperties.Subject(vmID), propertiesDir)
	return nil
}

// watchAndRunBoot polls the property tree for weft.boot/* and runs the
// boot.Runner once the request lands. Polling (not inotify): pkg/properties
// writes via tmp+rename which inotify would catch cleanly, but the polling
// loop is ~10 lines + zero deps, and the max latency is the poll interval.
// Idempotent: the Runner's sentinel check short-circuits on subsequent
// reboots.
//
// Bails after maxWait without a request — the operator may have stamped no
// boot config, in which case the sentinel is written anyway so future polls
// return immediately.
func watchAndRunBoot(propsDir string, runner *agentboot.Runner, rec *metrics.Recorder, logger *log.Logger) {
	const (
		pollEvery = 2 * time.Second
		maxWait   = 5 * time.Minute
	)
	ctx, cancel := context.WithTimeout(context.Background(), maxWait+30*time.Second)
	defer cancel()

	deadline := time.Now().Add(maxWait)
	for {
		// Sentinel already there? Subsequent reboot; nothing to do.
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
			start := time.Now()
			err := runner.Run(ctx, cfg)
			rec.RecordApply("boot", err, time.Since(start))
			if err != nil {
				logger.Printf("weft-microvm-agent: boot run: %v", err)
				return
			}
			logger.Printf("weft-microvm-agent: boot run ok ; sentinel written")
			return
		}

		if time.Now().After(deadline) {
			logger.Printf("weft-microvm-agent: boot : no config after %s, stamping sentinel + exiting watcher", maxWait)
			start := time.Now()
			err := runner.Run(ctx, agentboot.Config{}) // empty Run stamps the sentinel
			rec.RecordApply("boot", err, time.Since(start))
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
