package metrics

// V0.6-PERF-2 Phase E — Unit tests for the backend retry Prometheus metrics.

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// counterValue extracts the current value of a CounterVec for the given
// label values via a direct Gather call on the supplied registry.
func counterValue(t *testing.T, reg *prometheus.Registry, metricName string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != metricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelsMatch(m.GetLabel(), labels) {
				if c := m.GetCounter(); c != nil {
					return c.GetValue()
				}
			}
		}
	}
	return 0
}

// labelsMatch reports whether all entries in want appear in got.
func labelsMatch(got []*dto.LabelPair, want map[string]string) bool {
	found := 0
	for _, lp := range got {
		if v, ok := want[lp.GetName()]; ok && v == lp.GetValue() {
			found++
		}
	}
	return found == len(want)
}

// histogramSampleCount returns the number of observations recorded for a
// histogram identified by metricName and labels.
func histogramSampleCount(t *testing.T, reg *prometheus.Registry, metricName string, labels map[string]string) uint64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != metricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelsMatch(m.GetLabel(), labels) {
				if h := m.GetHistogram(); h != nil {
					return h.GetSampleCount()
				}
			}
		}
	}
	return 0
}

// TestRetry_MetricsIncrement drives three retry attempts and verifies the
// counter increments correctly.
func TestRetry_MetricsIncrement(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	// Simulate two retry attempts for PutObject.
	m.RecordBackendRetryWithMode("PutObject", "throttle_503", "standard")
	m.RecordBackendRetryWithMode("PutObject", "throttle_503", "standard")

	// Verify counter value is 2 (retries are attempts ≥ 2).
	v := counterValue(t, reg, "s3_backend_retries_total", map[string]string{
		"operation": "PutObject",
		"reason":    "throttle_503",
		"mode":      "standard",
	})
	if v != 2 {
		t.Errorf("s3_backend_retries_total: expected 2, got %.0f", v)
	}
}

// TestRetry_AttemptsPerRequest verifies the histogram observation for total
// attempts per logical request.
func TestRetry_AttemptsPerRequest(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	// Simulate a request that took 3 attempts.
	m.RecordBackendAttemptsPerRequest("PutObject", 3)

	count := histogramSampleCount(t, reg, "s3_backend_attempts_per_request", map[string]string{
		"operation": "PutObject",
	})
	if count != 1 {
		t.Errorf("s3_backend_attempts_per_request sample count: expected 1, got %d", count)
	}
}

// TestRetry_GiveUpCounter verifies the give-up counter increments for
// data-plane write operations.
func TestRetry_GiveUpCounter(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordBackendRetryGiveUp("PutObject", "throttle_503")

	v := counterValue(t, reg, "s3_backend_retry_give_ups_total", map[string]string{
		"operation":    "PutObject",
		"final_reason": "throttle_503",
	})
	if v != 1 {
		t.Errorf("s3_backend_retry_give_ups_total: expected 1, got %.0f", v)
	}
}

// TestRetry_BackoffHistogram verifies that backoff delays are recorded.
func TestRetry_BackoffHistogram(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordBackendRetryBackoff(200 * time.Millisecond)
	m.RecordBackendRetryBackoff(5 * time.Second)

	// Gather to verify there are 2 samples.
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "s3_backend_retry_backoff_seconds" {
			for _, m := range mf.GetMetric() {
				if h := m.GetHistogram(); h != nil {
					if h.GetSampleCount() != 2 {
						t.Errorf("s3_backend_retry_backoff_seconds sample count: expected 2, got %d", h.GetSampleCount())
					}
					return
				}
			}
		}
	}
	t.Error("s3_backend_retry_backoff_seconds metric not found")
}

// TestRetry_NilSafe verifies that all retry metric methods are nil-safe.
func TestRetry_NilSafe(t *testing.T) {
	var m *Metrics
	// None of these should panic.
	m.RecordBackendRetry("PutObject", "throttle_503")
	m.RecordBackendRetryWithMode("PutObject", "throttle_503", "standard")
	m.RecordBackendAttemptsPerRequest("PutObject", 3)
	m.RecordBackendRetryGiveUp("PutObject", "throttle_503")
	m.RecordBackendRetryBackoff(100 * time.Millisecond)
}
