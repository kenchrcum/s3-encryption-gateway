//go:build conformance

// Package conformance — loadtest_summary.go (V0.6-QA-1 Phase A).
//
// Adds structured JSON output to the existing soak harness. When the caller
// sets SOAK_JSON_OUT to a filesystem path, every testRangeLoad /
// testMultipartLoad run appends a single JSON object (one-per-line NDJSON
// style) matching the §4.2 schema of docs/plans/V0.6-QA-1-plan.md:
//
//   { "test": "...", "throughput_mbps": ..., "latency_ns": { p50,p95,p99 },
//     "errors": ..., "retries_total": ..., "heap_inuse_max_bytes": ...,
//     "cpu_seconds": ... }
//
// The file is opened O_APPEND so multiple consecutive runs on the same run
// (e.g. RangeRead then Multipart) land in the same file for the bench-macro
// script to aggregate.
//
// No new module dependency: percentiles are computed in-package by sort +
// index, and Prometheus retry counts are read from
// prometheus.DefaultGatherer (PERF-2 metrics live there).
//
// Design notes:
//   * Record is intentionally mirror-shaped to the plan's JSON schema; adding
//     a field here must also update docs/PERFORMANCE.md and the bench-compare
//     script (§6.1 threshold table).
//   * HeapSampler samples runtime.MemStats.HeapInuse every 500 ms and retains
//     the maximum. Cost is negligible; stops cleanly on ctx cancel.
//   * Percentiles are nearest-rank (Hyndman & Fan definition 7's simpler
//     sibling: ceil(p*N)-1). This matches what Go's `sort.Slice + index`
//     pattern produces and is what Prometheus exposes. See *Latency* ch. 3.

package conformance

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/client_golang/prometheus"
)

// LatencyPercentiles holds the three tracked latency percentiles in ns.
type LatencyPercentiles struct {
	P50 int64 `json:"p50"`
	P95 int64 `json:"p95"`
	P99 int64 `json:"p99"`
}

// SummaryRecord is the §4.2-schema JSON object written per load test.
// Field names match docs/plans/V0.6-QA-1-plan.md:4.2 exactly — do not rename
// without bumping schema_version in the wrapper file.
type SummaryRecord struct {
	Test              string             `json:"test"`
	ThroughputMBPS    float64            `json:"throughput_mbps"`
	LatencyNS         LatencyPercentiles `json:"latency_ns"`
	Errors            int64              `json:"errors"`
	RetriesTotal      float64            `json:"retries_total"`
	HeapInuseMaxBytes uint64             `json:"heap_inuse_max_bytes"`
	CPUSeconds        float64            `json:"cpu_seconds"`
}

// Percentiles computes p50/p95/p99 over a slice of durations (nanoseconds).
// Input is NOT mutated (a copy is sorted). An empty slice yields zeroes.
//
// Nearest-rank: for the p-th percentile of N elements, index is
// ceil(p/100 * N) - 1, clamped to [0, N-1]. This matches the Prometheus
// histogram "approximate" rank semantics and is what §3.2 / Enberg ch. 3
// recommend for log-normal distributions.
func Percentiles(samples []time.Duration) LatencyPercentiles {
	n := len(samples)
	if n == 0 {
		return LatencyPercentiles{}
	}
	sorted := make([]time.Duration, n)
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	idx := func(p float64) int {
		i := int(math.Ceil(p*float64(n))) - 1
		if i < 0 {
			i = 0
		}
		if i >= n {
			i = n - 1
		}
		return i
	}
	return LatencyPercentiles{
		P50: sorted[idx(0.50)].Nanoseconds(),
		P95: sorted[idx(0.95)].Nanoseconds(),
		P99: sorted[idx(0.99)].Nanoseconds(),
	}
}

// HeapSampler periodically reads runtime.MemStats.HeapInuse and retains the
// maximum. Start it before runWorkers, Stop it after, read Max() afterwards.
//
// Zero value is NOT ready: use NewHeapSampler.
type HeapSampler struct {
	max      uint64 // atomic; uint64 for consistency with MemStats
	stop     chan struct{}
	doneWG   sync.WaitGroup
	started  bool
	interval time.Duration
}

// NewHeapSampler returns a sampler that ticks at the given interval
// (default 500 ms when zero).
func NewHeapSampler(interval time.Duration) *HeapSampler {
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	return &HeapSampler{
		stop:     make(chan struct{}),
		interval: interval,
	}
}

// Start begins sampling in a background goroutine. Idempotent — second call
// is a no-op.
func (h *HeapSampler) Start() {
	if h.started {
		return
	}
	h.started = true
	h.doneWG.Add(1)
	go func() {
		defer h.doneWG.Done()
		ticker := time.NewTicker(h.interval)
		defer ticker.Stop()
		// Take an immediate first sample so very short runs record something.
		h.tick()
		for {
			select {
			case <-h.stop:
				return
			case <-ticker.C:
				h.tick()
			}
		}
	}()
}

func (h *HeapSampler) tick() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	for {
		cur := atomic.LoadUint64(&h.max)
		if ms.HeapInuse <= cur {
			return
		}
		if atomic.CompareAndSwapUint64(&h.max, cur, ms.HeapInuse) {
			return
		}
	}
}

// Stop halts the sampler and waits for the goroutine to return. Idempotent.
func (h *HeapSampler) Stop() {
	if !h.started {
		return
	}
	select {
	case <-h.stop:
		// already closed
	default:
		close(h.stop)
	}
	h.doneWG.Wait()
}

// Max returns the maximum observed HeapInuse in bytes.
func (h *HeapSampler) Max() uint64 {
	return atomic.LoadUint64(&h.max)
}

// ReadRetryCounterTotal scans the supplied prometheus.Gatherer (or
// DefaultGatherer if nil) and returns the sum of all samples of the
// s3_backend_retries_total counter across every label set.
//
// If the metric is not registered (the PERF-2 metrics only register under
// a gateway with a non-nil *metrics.Metrics), the function returns 0 with
// no error — that is the correct reading for a gateway that did not retry.
func ReadRetryCounterTotal(g prometheus.Gatherer) (float64, error) {
	if g == nil {
		g = prometheus.DefaultGatherer
	}
	families, err := g.Gather()
	if err != nil {
		return 0, fmt.Errorf("gather metrics: %w", err)
	}
	var total float64
	for _, mf := range families {
		if mf.GetName() != "s3_backend_retries_total" {
			continue
		}
		for _, m := range mf.Metric {
			if c := m.GetCounter(); c != nil {
				total += c.GetValue()
			}
		}
		break
	}
	return total, nil
}

// AppendJSONRecord writes a single JSON object (one line, newline-terminated)
// to the path named by SOAK_JSON_OUT. If that env var is empty, the call is
// a no-op — callers always invoke this; selection is environmental.
//
// Returns a non-nil error only for filesystem failures; a bad record schema
// (e.g. NaN) is surfaced by json.Marshal.
func AppendJSONRecord(envVarPath string, rec SummaryRecord) error {
	if envVarPath == "" {
		return nil
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal summary record: %w", err)
	}
	f, err := os.OpenFile(envVarPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", envVarPath, err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("write %s: %w", envVarPath, err)
	}
	return nil
}

// _ forces the prometheus client_model dep to be retained even when
// benchmarks do not directly use *dto.MetricFamily, ensuring the go.mod
// entry is explicit. Removing this is safe but subtle — see
// https://github.com/golang/go/wiki/Modules#unused-imports.
var _ = (*dto.MetricFamily)(nil)
