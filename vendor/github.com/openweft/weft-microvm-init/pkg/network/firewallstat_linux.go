//go:build linux

package network

import (
	"fmt"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// ReadFirewallStatus inspects the kernel "weft-fw" nftables table
// and returns a [[pod.FirewallStatus]] snapshot. PublishedAtUnix is
// left zero — the emitter stamps it just before publishing.
//
// Errors are folded into the returned status (Overall=Degraded,
// LastError=err.Error()) rather than propagated as a Go error. The
// emitter publishes status unconditionally ; a netlink hiccup
// shouldn't stop the next publish, and the operator wants the bad
// state on the dashboard rather than silent black-hole.
func ReadFirewallStatus() pod.FirewallStatus {
	c, err := nft.New(nft.AsLasting())
	if err != nil {
		return pod.FirewallStatus{Overall: "Degraded", LastError: fmt.Sprintf("nftables open: %v", err)}
	}
	defer c.CloseLasting()

	tables, err := c.ListTablesOfFamily(nft.TableFamilyINet)
	if err != nil {
		return pod.FirewallStatus{Overall: "Degraded", LastError: fmt.Sprintf("list tables: %v", err)}
	}
	var ourTable *nft.Table
	for _, t := range tables {
		if t.Name == firewallTableName {
			ourTable = t
			break
		}
	}
	if ourTable == nil {
		// No table yet — agent is up, reconciler hasn't received a
		// desired-state publish. Healthy idle.
		return pod.FirewallStatus{Overall: "Healthy"}
	}

	chains, err := c.ListChainsOfTableFamily(nft.TableFamilyINet)
	if err != nil {
		return pod.FirewallStatus{
			Overall:        "Degraded",
			TableInstalled: true,
			LastError:      fmt.Sprintf("list chains: %v", err),
		}
	}
	total := 0
	var dropPkts, dropBytes uint64
	for _, ch := range chains {
		if ch.Table == nil || ch.Table.Name != firewallTableName {
			continue
		}
		rules, err := c.GetRules(ourTable, ch)
		if err != nil {
			return pod.FirewallStatus{
				Overall:        "Degraded",
				TableInstalled: true,
				LastError:      fmt.Sprintf("get rules in %s: %v", ch.Name, err),
			}
		}
		total += len(rules)
		// Walk the rules looking for the tail counter+drop rule
		// the reconciler installs on the input chain. Pattern :
		// rule contains an *expr.Counter immediately preceding
		// an *expr.Verdict{Kind: VerdictDrop}. Sum across all
		// matching rules (defense-in-depth in case a future
		// reconciler grows multiple counter+drop pairs).
		if ch.Name != "input" {
			continue
		}
		for _, r := range rules {
			pkts, bytes, ok := dropCounterFromRule(r)
			if !ok {
				continue
			}
			dropPkts += pkts
			dropBytes += bytes
		}
	}
	return pod.FirewallStatus{
		Overall:        "Healthy",
		TableInstalled: true,
		RulesInstalled: total,
		DropsPackets:   dropPkts,
		DropsBytes:     dropBytes,
	}
}

// dropCounterFromRule returns (packets, bytes, true) when r
// matches the "counter + drop" tail rule pattern. Scans the
// rule's exprs for an *expr.Counter immediately followed by a
// drop verdict ; ignores rules that have a counter but accept
// (those don't represent firewall drops).
func dropCounterFromRule(r *nft.Rule) (uint64, uint64, bool) {
	if r == nil {
		return 0, 0, false
	}
	var ctr *expr.Counter
	for i, e := range r.Exprs {
		if c, ok := e.(*expr.Counter); ok {
			// Look ahead for the drop verdict.
			for j := i + 1; j < len(r.Exprs); j++ {
				if v, ok := r.Exprs[j].(*expr.Verdict); ok {
					if v.Kind == expr.VerdictDrop {
						ctr = c
					}
					break
				}
			}
			if ctr != nil {
				break
			}
		}
	}
	if ctr == nil {
		return 0, 0, false
	}
	return ctr.Packets, ctr.Bytes, true
}
