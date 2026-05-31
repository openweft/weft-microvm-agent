// Package metrics owns the Prometheus instrumentation for the
// in-guest weft-microvm-agent. The daemon registers a small surface :
//
//   - weft_microvm_agent_build_info{version,commit,date}      — boot fingerprint
//   - weft_microvm_agent_apply_total{concern,result}          — Apply call counter
//   - weft_microvm_agent_apply_duration_seconds{concern}      — Apply latency histogram
//   - weft_microvm_agent_nats_connected                       — 0/1 gauge
//
// Each NATS-driven subscriber (mesh / mounts / sshkeys / properties /
// boot) calls Recorder.RecordApply after running its ApplyFunc ; the
// concern label routes the observation to the right time-series.
// Mirrors the shape of openweft/weft-network's internal/metrics
// package — same Registry-not-Default policy, same Handler() wiring.
package metrics

import (
	"net/http"
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

	buildInfo      *prometheus.GaugeVec
	applyTotal     *prometheus.CounterVec
	applyDuration  *prometheus.HistogramVec
	natsConnected  prometheus.Gauge
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
	}
	r.reg.MustRegister(r.buildInfo, r.applyTotal, r.applyDuration, r.natsConnected)
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
