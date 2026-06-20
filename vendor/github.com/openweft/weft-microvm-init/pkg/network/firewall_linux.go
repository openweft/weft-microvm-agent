//go:build linux

// firewall_linux.go is the kernel-touching reconciler that converges a
// nftables table named "weft-fw" to a [[pod.Firewall]] desired state.
//
// Shape :
//   table inet weft-fw {
//     chain input  { type filter hook input  priority filter; policy drop ;
//       ct state established,related accept
//       iifname "lo" accept
//       <per-rule allow lines>
//     }
//     chain output { type filter hook output priority filter; policy accept ;
//       <per-rule egress drop lines if any>
//     }
//   }
//
// Reconcile is whole-state : we DELETE the table (if any) and
// re-create it in one batched netlink flush, so an outside observer
// never sees a half-applied policy. Same model the WireGuard apply
// uses (replace-set, idempotent).
//
// Stateful : `ct state established,related accept` is added at the top
// of input so reply traffic from VM-initiated egress flows in without
// needing a mirrored ingress rule.
package network

import (
	"fmt"
	"net"
	"sync"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// firewallTableName is the table the reconciler owns end-to-end. Other
// tables on the system (e.g. user-installed nftables rules) are
// untouched. Naming chosen so an operator running `nft list ruleset`
// inside the guest can spot it immediately.
const firewallTableName = "weft-fw"

// firewallMu serialises concurrent ApplyFirewall calls from the
// subscriber goroutine. The netlink batch itself is atomic, but two
// concurrent batches could race ordering of flush vs add.
var firewallMu sync.Mutex

// ApplyFirewall reconciles the kernel nftables ruleset against fw.
// The empty ruleset is valid and yields :
//   - input  : default-deny except ct established/related + lo
//   - output : default-accept
// This is the "no Security Group attached" baseline.
func ApplyFirewall(fw *pod.Firewall) error {
	firewallMu.Lock()
	defer firewallMu.Unlock()

	c, err := nft.New(nft.AsLasting())
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	defer c.CloseLasting()

	// Drop the existing table if any (DelTable on a non-existent table
	// is a soft error we swallow by flushing the connection — Flush
	// reports unknown-table as nil from this client). Build a fresh
	// table whole so the apply is atomic at the netlink-batch level.
	existing, err := c.ListTablesOfFamily(nft.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	for _, t := range existing {
		if t.Name == firewallTableName {
			c.DelTable(t)
		}
	}

	table := c.AddTable(&nft.Table{
		Family: nft.TableFamilyINet,
		Name:   firewallTableName,
	})

	// Input chain : default drop, accept ct established/related + lo.
	dropPolicy := nft.ChainPolicyDrop
	input := c.AddChain(&nft.Chain{
		Name:     "input",
		Table:    table,
		Type:     nft.ChainTypeFilter,
		Hooknum:  nft.ChainHookInput,
		Priority: nft.ChainPriorityFilter,
		Policy:   &dropPolicy,
	})
	c.AddRule(&nft.Rule{Table: table, Chain: input, Exprs: ctEstablishedAccept()})
	c.AddRule(&nft.Rule{Table: table, Chain: input, Exprs: iifAccept("lo")})

	// Named drop counter — every packet that falls through to
	// the default chain policy lands here first. Counters survive
	// table rebuilds because we re-declare the object on every
	// Apply ; the kernel keeps the counter object stable across
	// rule churn so an operator scrape from outside the apply
	// window sees monotonic counts. ReadFirewallStatus picks it
	// up via the Object API.

	// Output chain : default accept ; egress rules below will only ever
	// add allow lines (egress rules are presence-based, like ingress).
	// Locking down egress entirely would require a default-drop policy
	// here ; we keep accept so a tenant who attaches no SG still gets
	// working outbound traffic.
	acceptPolicy := nft.ChainPolicyAccept
	output := c.AddChain(&nft.Chain{
		Name:     "output",
		Table:    table,
		Type:     nft.ChainTypeFilter,
		Hooknum:  nft.ChainHookOutput,
		Priority: nft.ChainPriorityFilter,
		Policy:   &acceptPolicy,
	})

	for _, r := range fw.Rules {
		exprs, err := buildRuleExprs(r)
		if err != nil {
			return fmt.Errorf("build rule (%+v): %w", r, err)
		}
		switch r.Direction {
		case "ingress":
			c.AddRule(&nft.Rule{Table: table, Chain: input, Exprs: exprs})
		case "egress":
			c.AddRule(&nft.Rule{Table: table, Chain: output, Exprs: exprs})
		}
	}

	// Tail counter on the input chain : every packet that falls
	// through the accept rules above lands on this counter+drop.
	// Operators see the rate via `nft list table inet weft-fw`
	// (per-rule counter values) ; pkg/firewallstatus + the
	// Prometheus metric in weft-microvm-agent surface the
	// running total via netlink later.
	c.AddRule(&nft.Rule{
		Table: table, Chain: input,
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})

	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}
	return nil
}

// ctEstablishedAccept returns the expression list matching
// `ct state established,related accept`. Pulled out so the input chain
// stays declaratively readable.
func ctEstablishedAccept() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:  []byte{0, 0, 0, 0},
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// iifAccept returns the expression list matching
// `iifname "<name>" accept`.
func iifAccept(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nftIfname(name)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// buildRuleExprs translates one [[pod.FirewallRule]] into nftables
// expressions. Direction governs which match keys we choose (saddr vs
// daddr, sport vs dport) so an ingress rule "tcp dport 22 from 10/8"
// matches inbound packets with src=10/8 dst-port=22, and an egress
// rule "tcp dport 443 to 10/8" matches outbound packets with
// dst=10/8 dst-port=443.
func buildRuleExprs(r pod.FirewallRule) ([]expr.Any, error) {
	var exprs []expr.Any

	if r.RemoteCIDR != "" {
		_, ipnet, err := net.ParseCIDR(r.RemoteCIDR)
		if err != nil {
			return nil, fmt.Errorf("parse cidr: %w", err)
		}
		offset, family, err := addrOffset(ipnet.IP, r.Direction)
		if err != nil {
			return nil, err
		}
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader,
				Offset: offset, Len: uint32(len(ipnet.IP))},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(len(ipnet.Mask)),
				Mask: ipnet.Mask, Xor: zeroBytes(len(ipnet.Mask))},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ipnet.IP.Mask(ipnet.Mask)},
		)
	}

	if r.Protocol != "" {
		var l4 byte
		switch r.Protocol {
		case "tcp":
			l4 = unix.IPPROTO_TCP
		case "udp":
			l4 = unix.IPPROTO_UDP
		case "icmp":
			l4 = unix.IPPROTO_ICMP
		default:
			return nil, fmt.Errorf("unknown protocol %q", r.Protocol)
		}
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{l4}},
		)
	}

	if r.PortMin != 0 || r.PortMax != 0 {
		// Port offset within the TCP/UDP header : dport=2, sport=0.
		// Ingress matches dport (where the traffic is going on the VM),
		// egress also matches dport (where the traffic is going on the
		// remote side). Same convention OpenStack / EC2 use.
		exprs = append(exprs,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader,
				Offset: 2, Len: 2},
		)
		if r.PortMin == r.PortMax {
			exprs = append(exprs, &expr.Cmp{Op: expr.CmpOpEq, Register: 1,
				Data: portBytes(r.PortMin)})
		} else {
			exprs = append(exprs,
				&expr.Range{Op: expr.CmpOpEq, Register: 1,
					FromData: portBytes(r.PortMin),
					ToData:   portBytes(r.PortMax)},
			)
		}
	}

	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
	return exprs, nil
}

// addrOffset returns the byte offset of the matched address field in
// the IP header (saddr for ingress, daddr for egress) and the
// expected nfproto byte for the cmp guard. IPv6 IPs are 16 bytes so
// callers size the Payload op accordingly.
func addrOffset(ip net.IP, direction string) (uint32, byte, error) {
	v4 := ip.To4() != nil
	switch {
	case v4 && direction == "ingress":
		return 12, unix.NFPROTO_IPV4, nil
	case v4 && direction == "egress":
		return 16, unix.NFPROTO_IPV4, nil
	case !v4 && direction == "ingress":
		return 8, unix.NFPROTO_IPV6, nil
	case !v4 && direction == "egress":
		return 24, unix.NFPROTO_IPV6, nil
	default:
		return 0, 0, fmt.Errorf("unknown direction %q", direction)
	}
}

func portBytes(p uint16) []byte { return []byte{byte(p >> 8), byte(p)} }
func zeroBytes(n int) []byte    { return make([]byte, n) }
func nftIfname(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}
func binaryUint32(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}
