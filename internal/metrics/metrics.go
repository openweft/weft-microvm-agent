// Package metrics owns the Prometheus instrumentation for the
// in-guest weft-microvm-agent. The daemon registers a small surface :
//
//   - weft_microvm_agent_build_info{version,commit,date}            — boot fingerprint
//   - weft_microvm_agent_apply_total{concern,result}                — Apply call counter
//   - weft_microvm_agent_apply_duration_seconds{concern}            — Apply latency histogram
//   - weft_microvm_agent_nats_connected                             — 0/1 gauge
//   - weft_microvm_agent_firewall_status_publishes_total{result}    — firewallstatus.Emitter publishOnce counter
//   - weft_microvm_agent_firewall_drops_packets_total               — nftables drop tail-rule packet counter
//   - weft_microvm_agent_firewall_drops_bytes_total                 — nftables drop tail-rule byte counter
//
// Each NATS-driven subscriber (mesh / mounts / sshkeys / properties /
// boot) calls Recorder.RecordApply after running its ApplyFunc ; the
// concern label routes the observation to the right time-series.
// The firewallstatus emitter wires Recorder.RecordFirewallStatusPublish
// via its PublishHook seam — parallel to RecordApply but specific to
// the publish-loop reverse direction. The same emitter additionally
// calls Recorder.RecordFirewallDrops on every successful read so the
// kernel's counter+drop tail-rule surfaces as a monotonic Prometheus
// counter pair (rate() over them gives the live drop pps / Bps).
//
// Mirrors the shape of openweft/weft-network's internal/metrics
// package — same Registry-not-Default policy, same Handler() wiring.
package metrics

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Recorder bundles the metrics + the helpers subscribers call from
// their Apply hot path. Construct once at startup ; share by pointer.
//
// The recorder owns its own prometheus.Registry rather than using
// promauto's default — keeps test isolation tight (each New() is a
// clean slate) and prevents process-global pollution that would
// surface as collisions in unit tests run in the same binary.
type Recorder struct {
	reg *prometheus.Registry

	buildInfo               *prometheus.GaugeVec
	applyTotal              *prometheus.CounterVec
	applyDuration           *prometheus.HistogramVec
	natsConnected           prometheus.Gauge
	firewallStatusPublishes *prometheus.CounterVec
	firewallDropsPackets    prometheus.Counter
	firewallDropsBytes      prometheus.Counter

	// firewallDrops tracks the reset-aware accumulator state for the
	// nftables drop tail-rule counter pair. The kernel resets its
	// counter to 0 every time the table is rebuilt (a reconcile flush
	// + reapply), but Prometheus counters must be monotonic — so we
	// keep the last observed kernel value and only ever Add(delta>0)
	// to the published counter. On reset (current < last) we treat
	// the current value as a fresh accumulation and Add(current).
	firewallDropsMu      sync.Mutex
	firewallDropsLastPkt uint64
	firewallDropsLastByt uint64
}

// New builds + registers the recorder against a fresh registry.
// version / commit / date come from main.go's -ldflags stamps so the
// build_info metric is useful in a multi-VM scrape.
func New(version, commit, date string) *Recorder {
	r := &Recorder{
		reg: prometheus.NewRegistry(),
		buildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "weft_microvm_agent_build_info",
			Help: "Build fingerprint of the running weft-microvm-agent binary. Value is always 1 ; the labels carry the version / commit / date stamped at build time.",
		}, []string{"version", "commit", "date"}),
		applyTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "weft_microvm_agent_apply_total",
			Help: "Total NATS-driven Apply calls, labelled by concern (mesh|mounts|sshkeys|properties|boot) and result (ok|error).",
		}, []string{"concern", "result"}),
		applyDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "weft_microvm_agent_apply_duration_seconds",
			Help:    "Apply latency histogram, labelled by concern. Default Prometheus buckets (5 ms → 10 s) fit the netlink / file-write band of the agent's Apply RPCs.",
			Buckets: prometheus.DefBuckets,
		}, []string{"concern"}),
		natsConnected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "weft_microvm_agent_nats_connected",
			Help: "1 if the agent currently holds a NATS connection ; 0 otherwise. Flipped by the subscriber lifecycle.",
		}),
		firewallStatusPublishes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "weft_microvm_agent_firewall_status_publishes_total",
			Help: "Total FirewallStatus publishOnce invocations from the in-guest firewallstatus emitter, labelled by result (ok|error). Parallel to apply_total but specific to the reverse-direction publish loop.",
		}, []string{"result"}),
		firewallDropsPackets: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "weft_microvm_agent_firewall_drops_packets_total",
			Help: "Total packets dropped by the nftables drop tail-rule on the in-guest firewall input chain, accumulated across kernel-table rebuilds (counter resets handled by the recorder). rate() yields live drop pps.",
		}),
		firewallDropsBytes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "weft_microvm_agent_firewall_drops_bytes_total",
			Help: "Total bytes dropped by the nftables drop tail-rule on the in-guest firewall input chain, accumulated across kernel-table rebuilds (counter resets handled by the recorder). rate() yields live drop Bps.",
		}),
	}
	r.reg.MustRegister(r.buildInfo, r.applyTotal, r.applyDuration, r.natsConnected, r.firewallStatusPublishes, r.firewallDropsPackets, r.firewallDropsBytes)
	r.buildInfo.WithLabelValues(version, commit, date).Set(1)
	return r
}

// RecordApply records one Apply invocation : increments the counter
// (labelled ok / error from err) and observes the histogram (labelled
// by concern only — error vs ok latency are usually different
// distributions but the volume here is too low to justify the extra
// cardinality, and the counter already carries the success ratio).
//
// Safe to call with a nil receiver — subscribers without metrics
// wiring (tests, non-prod main()s) get a no-op. Matches the pattern
// other Anthropic-style daemons use to keep test setup cheap.
func (r *Recorder) RecordApply(concern string, err error, dur time.Duration) {
	if r == nil {
		return
	}
	result := "ok"
	if err != nil {
		result = "error"
	}
	r.applyTotal.WithLabelValues(concern, result).Inc()
	r.applyDuration.WithLabelValues(concern).Observe(dur.Seconds())
}

// RecordFirewallStatusPublish records one Emitter.publishOnce
// invocation in the firewallstatus loop : increments the counter
// labelled ok / error from err. Parallel to RecordApply (same ok /
// error convention) but separate metric because publish-loop and
// apply-loop have different operator narratives (the apply
// histogram only makes sense for the reconcile side).
//
// Wired from cmd/weft-microvm-agent's startFirewallStatus via
// firewallstatus.Emitter.SetMetricsHook so the hook receives every
// publish outcome — happy path or transient transport hiccup.
//
// Nil-receiver-safe like RecordApply / SetNATSConnected so tests
// that don't construct a Recorder still tick along.
func (r *Recorder) RecordFirewallStatusPublish(err error) {
	if r == nil {
		return
	}
	result := "ok"
	if err != nil {
		result = "error"
	}
	r.firewallStatusPublishes.WithLabelValues(result).Inc()
}

// RecordFirewallDrops folds one observation of the nftables drop
// tail-rule counter pair into the monotonic Prometheus counters.
//
// The kernel counter is reset to 0 every time the firewall reconciler
// rebuilds the table (flush + reapply ; happens on every desired-state
// change). Prometheus counters, however, are supposed to be monotonic
// so rate() / increase() can detect process restarts vs real activity
// via the standard counter-reset heuristic.
//
// The accumulator handles this : we keep the last raw (packets, bytes)
// value we saw the kernel report. On each call :
//
//   - growth (current >= last) → Add(current - last) ; the published
//     counter grows by the delta only.
//   - reset (current < last)   → the kernel rebuilt its table ; we
//     reseed last := 0 and Add(current) so the next interval's worth
//     of drops shows up immediately.
//
// Packets and bytes are tracked independently in case the two
// counters drift across a rebuild boundary (they always reset
// together in practice, but the field-level guard keeps the
// invariant honest).
//
// Nil-receiver-safe like RecordApply / RecordFirewallStatusPublish.
// Guarded by a mutex because the firewallstatus emitter is the sole
// caller today but the field is exposed to any future caller (e.g.
// a pull-model reconciler that ticks on a different schedule).
func (r *Recorder) RecordFirewallDrops(packets, bytes uint64) {
	if r == nil {
		return
	}
	r.firewallDropsMu.Lock()
	defer r.firewallDropsMu.Unlock()

	// Packets : delta if growing, full current value if the kernel
	// reset (current < last).
	if packets < r.firewallDropsLastPkt {
		r.firewallDropsLastPkt = 0
	}
	if delta := packets - r.firewallDropsLastPkt; delta > 0 {
		r.firewallDropsPackets.Add(float64(delta))
	}
	r.firewallDropsLastPkt = packets

	// Bytes : symmetric to packets.
	if bytes < r.firewallDropsLastByt {
		r.firewallDropsLastByt = 0
	}
	if delta := bytes - r.firewallDropsLastByt; delta > 0 {
		r.firewallDropsBytes.Add(float64(delta))
	}
	r.firewallDropsLastByt = bytes
}

// SetNATSConnected flips the gauge. Call once from the NATS
// subscriber lifecycle on connect (true) ; call false on close.
// Nil-receiver-safe like RecordApply.
func (r *Recorder) SetNATSConnected(connected bool) {
	if r == nil {
		return
	}
	v := 0.0
	if connected {
		v = 1.0
	}
	r.natsConnected.Set(v)
}

// Handler returns the http.Handler serving /metrics. Caller wires it
// into a dedicated listener (different port from the Introspect gRPC)
// so the scrape surface doesn't share fate with the control plane.
func (r *Recorder) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// Registry exposes the underlying prometheus.Registry for tests + the
// rare case a caller wants to register a domain-specific metric
// alongside ours.
func (r *Recorder) Registry() *prometheus.Registry { return r.reg }
