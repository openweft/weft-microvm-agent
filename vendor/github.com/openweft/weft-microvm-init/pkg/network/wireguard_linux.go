//go:build linux

// wireguard_linux.go brings up a kernel WireGuard interface (wg0) by
// delegating to grpc-transports/wireguard's public BringUp (kernel
// backend). Same code path the host side (weft agent --proxy) uses for its
// own wg interface, so additions like cosigner verification or key
// rotation only need to land in one library.
//
// The pod spec's WireGuard.Address is a full CIDR (e.g. "10.9.0.1/24")
// because the guest expects a connected route to the overlay subnet;
// BringUp itself only installs a /32, so this wrapper re-adds the
// broader prefix after to keep that semantic identical to the legacy
// raw-netlink path.
package network

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"syscall"

	wgtransport "github.com/grpc-transports/wireguard"
	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// applier holds the BringUp Closer across re-applies. When the host
// republishes a mesh update (peers added/removed), we ask the underlying
// lib to re-bring-up the same interface: that path is idempotent (link
// reused, peers replaced via ReplacePeers=true) so it doubles as an
// update channel without tearing the netdev down between applies.
var (
	applierMu sync.Mutex
	applier   wgtransport.Closer
)

// ApplyWireGuard creates the WireGuard interface, configures its device
// (key, port, peers) and brings it up with the overlay address. Idempotent:
// re-applying replaces peers and re-asserts the address.
func ApplyWireGuard(wg *pod.WireGuard) error {
	if wg == nil {
		return nil
	}
	iface := wg.Interface
	if iface == "" {
		iface = "wg0"
	}

	// Validate the private key locally so we surface the same error the
	// legacy path produced ("must be N bytes") rather than the lib's
	// "decode key: invalid base64" deeper down the stack.
	priv, err := base64.StdEncoding.DecodeString(wg.PrivateKey)
	if err != nil {
		return fmt.Errorf("wireguard private_key: %w", err)
	}
	if len(priv) != keyLen {
		return fmt.Errorf("wireguard private_key must be %d bytes, got %d", keyLen, len(priv))
	}

	// Parse the overlay address up-front so a malformed CIDR fails fast,
	// before we touch the kernel.
	var (
		overlayIP    net.IP
		overlayIPNet *net.IPNet
	)
	if wg.Address != "" {
		overlayIP, overlayIPNet, err = net.ParseCIDR(wg.Address)
		if err != nil {
			return fmt.Errorf("wireguard address %q: %w", wg.Address, err)
		}
	}

	peers, err := buildPeers(wg.Peers)
	if err != nil {
		return err
	}

	localIP, err := overlayLocalIP(overlayIP)
	if err != nil {
		return err
	}

	// Stage a private-key file the lib can load. It expects a path
	// rather than an inline key for ServerConfig; the simplest
	// faithful answer is to materialise wg.PrivateKey to a tmpfile
	// we then point at.
	keyPath, err := stagePrivateKey(wg.PrivateKey)
	if err != nil {
		return err
	}
	defer cleanupTmpKey(keyPath)

	cfg := wgtransport.ServerConfig{
		Backend:        wgtransport.BackendKernel,
		InterfaceName:  iface,
		PrivateKeyPath: keyPath,
		LocalIP:        localIP,
		ListenPort:     wg.ListenPort,
		Peers:          peers,
		Logger:         log.New(log.Writer(), "", log.LstdFlags),
	}

	closer, err := wgtransport.BringUp(cfg)
	if err != nil {
		return fmt.Errorf("wireguard bring-up %s: %w", iface, err)
	}

	// Replace any previous closer — the lib reuses the existing link
	// when InterfaceName matches, so the new closer is the live one.
	applierMu.Lock()
	applier = closer
	applierMu.Unlock()

	// Re-add the broader on-link prefix (e.g. /24) so peers inside
	// the overlay subnet that aren't enumerated in AllowedIPs still
	// reach the interface via the connected route — matching the
	// legacy behaviour where wg.Address was assigned with its full
	// mask.
	if overlayIPNet != nil {
		idx, err := ifaceIndex(iface)
		if err != nil {
			return fmt.Errorf("resolve %s after bring-up: %w", iface, err)
		}
		if err := addrAdd(idx, overlayIP, overlayIPNet); err != nil && !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("addr add %s on %s: %w", wg.Address, iface, err)
		}
	}
	return nil
}

// stagePrivateKey writes the (already base64-encoded) key to a 0600
// tmpfile so wgtransport.ServerConfig.PrivateKeyPath has something to
// point at. The lib only accepts a path; we'd rather not hand it a
// long-lived on-disk key just because it lacks an inline-key field.
func stagePrivateKey(b64 string) (string, error) {
	f, err := os.CreateTemp("", "wg-priv-*")
	if err != nil {
		return "", fmt.Errorf("stage wg private key: %w", err)
	}
	if _, err := f.WriteString(b64 + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("stage wg private key: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("stage wg private key: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("stage wg private key: %w", err)
	}
	return f.Name(), nil
}

func cleanupTmpKey(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}