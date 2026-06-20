// wgpeers.go holds the pure (no syscall, OS-agnostic) bits of the
// pod-spec → wgtransport translation so they're unit-testable on any
// host. The kernel bring-up itself lives in wireguard_linux.go.
package network

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"

	wgtransport "github.com/grpc-transports/wireguard"
	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// keyLen is the size of a Curve25519 WireGuard key.
const keyLen = 32

// buildPeers translates the pod WGPeer list to the transport lib's Peer
// shape. The lib expects base64-encoded keys and netip.Prefix AllowedIPs;
// the pod spec ships base64 keys (verified here) and string CIDRs.
func buildPeers(in []pod.WGPeer) ([]wgtransport.Peer, error) {
	out := make([]wgtransport.Peer, 0, len(in))
	for i, p := range in {
		pub, err := base64.StdEncoding.DecodeString(p.PublicKey)
		if err != nil || len(pub) != keyLen {
			return nil, fmt.Errorf("peer %d public_key: invalid base64/length", i)
		}
		allowed := make([]netip.Prefix, 0, len(p.AllowedIPs))
		for _, cidr := range p.AllowedIPs {
			pref, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, fmt.Errorf("peer %d allowed_ip %q: %w", i, cidr, err)
			}
			allowed = append(allowed, pref)
		}
		out = append(out, wgtransport.Peer{
			PublicKey:           p.PublicKey,
			AllowedIPs:          allowed,
			Endpoint:            p.Endpoint,
			PersistentKeepalive: p.PersistentKeepalive,
		})
	}
	return out, nil
}

// overlayLocalIP turns the net.IP parsed from the pod's CIDR into a
// netip.Addr the transport lib's BringUp consumes. When no overlay
// address is configured the wg interface still goes up — BringUp itself
// fails on an invalid LocalIP, so an explicit error here is clearer.
func overlayLocalIP(ip net.IP) (netip.Addr, error) {
	if ip == nil {
		return netip.Addr{}, fmt.Errorf("wireguard address is required")
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("wireguard address %v: not a valid IP", ip)
	}
	return a.Unmap(), nil
}
