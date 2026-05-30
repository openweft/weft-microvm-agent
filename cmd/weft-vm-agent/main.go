// weft-vm-agent runs inside an openweft micro-VM. It serves the read-only
// Introspect gRPC API (process table, …) to an operator CLI over the kernel
// WireGuard overlay (wg0), and — when pointed at the event bus — subscribes
// to mesh updates and re-applies its wg0 peer set whenever vzd publishes a
// new desired state.
//
// The gRPC server uses insecure credentials: transport confidentiality is
// provided by wg0, like the rest of the platform's overlay-secured listeners.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/nats-io/nats.go"
	"github.com/openweft/weft-microvm-init/pkg/pod"
	introspectv1 "github.com/openweft/weft-proto/introspectv1"
	"github.com/openweft/weft-vm-agent/pkg/cubefs"
	"github.com/openweft/weft-vm-agent/pkg/introspectsrv"
	agentmesh "github.com/openweft/weft-vm-agent/pkg/mesh"
	agentmounts "github.com/openweft/weft-vm-agent/pkg/mounts"
	"google.golang.org/grpc"
)

func main() {
	listenAddr := flag.String("listen", "0.0.0.0:51999", "address to serve the Introspect API on (set to the VM's wg0 IP:port)")
	meshVMID := flag.String("mesh-vm-id", "", "this VM's id; when set, subscribe to mesh updates on the event bus")
	mountsVMID := flag.String("mounts-vm-id", "", "this VM's id; when set, subscribe to dynamic share-mount updates on the event bus")
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
			logger.Fatalf("weft-vm-agent: share mounts: %v", err)
		}
	}

	if *meshVMID != "" {
		if err := startMesh(*natsURL, *natsCreds, *meshVMID, logger); err != nil {
			logger.Fatalf("weft-vm-agent: mesh: %v", err)
		}
	}

	if *mountsVMID != "" {
		if err := startMounts(*natsURL, *natsCreds, *mountsVMID, reg, logger); err != nil {
			logger.Fatalf("weft-vm-agent: mounts: %v", err)
		}
	}

	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		logger.Fatalf("weft-vm-agent: listen %s: %v", *listenAddr, err)
	}

	srv := grpc.NewServer()
	introspectv1.RegisterIntrospectServer(srv, introspectsrv.New())

	logger.Printf("weft-vm-agent: Introspect serving on %s", *listenAddr)
	if err := srv.Serve(lis); err != nil {
		logger.Fatalf("weft-vm-agent: serve: %v", err)
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
	logger.Printf("weft-vm-agent: mesh subscribed on %s", agentmesh.Subject(vmID))
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
	logger.Printf("weft-vm-agent: mounts subscribed on %s", agentmounts.Subject(vmID))
	return nil
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
		logger.Printf("weft-vm-agent: mounted %s at %s", m.ID, m.MountPoint)
	}
	return nil
}
