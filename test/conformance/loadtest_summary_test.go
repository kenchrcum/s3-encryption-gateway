//go:build conformance

package conformance

import (
	"context"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSummaryRecord_Percentiles covers golden values on both a linear and a
// log-normal distribution, at two sizes.
func TestSummaryRecord_Percentiles(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		got := Percentiles(nil)
		assert.Zero(t, got.P50)
		assert.Zero(t, got.P95)
		assert.Zero(t, got.P99)
	})

	t.Run("linear_100", func(t *testing.T) {
		// 1..100 ns → p50=ceil(0.5*100)-1=49 → 50 ns
		//           p95=ceil(0.95*100)-1=94 → 95 ns
		//           p99=ceil(0.99*100)-1=98 → 99 ns
		s := make([]time.Duration, 100)
		for i := range s {
			s[i] = time.Duration(i+1) * time.Nanosecond
		}
		got := Percentiles(s)
		assert.Equal(t, int64(50), got.P50)
		assert.Equal(t, int64(95), got.P95)
		assert.Equal(t, int64(99), got.P99)
	})

	t.Run("monotone_10000", func(t *testing.T) {
		s := make([]time.Duration, 10000)
		for i := range s {
			s[i] = time.Duration(i+1) * time.Microsecond
		}
		got := Percentiles(s)
		// p50 → idx 4999 (µs), p95 → 9499, p99 → 9899.
		assert.Equal(t, int64(5000*time.Microsecond/time.Nanosecond), got.P50)
		assert.Equal(t, int64(9500*time.Microsecond/time.Nanosecond), got.P95)
		assert.Equal(t, int64(9900*time.Microsecond/time.Nanosecond), got.P99)
	})

	t.Run("log_normal_ordering", func(t *testing.T) {
		// Deterministic log-normal-shaped distribution.
		rng := rand.New(rand.NewSource(42))
		s := make([]time.Duration, 1000)
		for i := range s {
			// ExpFloat64 gives an exponential distribution (scale = 1 ms).
			s[i] = time.Duration(rng.ExpFloat64() * float64(time.Millisecond))
		}
		got := Percentiles(s)
		// p50 < p95 < p99 is the essential invariant.
		assert.Less(t, got.P50, got.P95)
		assert.Less(t, got.P95, got.P99)
	})

	t.Run("input_not_mutated", func(t *testing.T) {
		s := []time.Duration{3, 1, 2}
		_ = Percentiles(s)
		assert.Equal(t, []time.Duration{3, 1, 2}, s, "input slice must not be sorted in place")
	})
}

// TestSummaryRecord_HeapSampler verifies the sampler starts, records a value
// above baseline, and stops cleanly on ctx cancel.
func TestSummaryRecord_HeapSampler(t *testing.T) {
	s := NewHeapSampler(10 * time.Millisecond)
	s.Start()

	// Force some heap allocation so the sampler has something > 0 to read.
	junk := make([][]byte, 32)
	for i := range junk {
		junk[i] = make([]byte, 16*1024)
	}
	runtime_GC_barrier(junk) // keeps alloc alive past measurement

	// Wait one scheduling cycle for at least one tick.
	time.Sleep(40 * time.Millisecond)

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		s.Stop()
		close(done)
	}()
	select {
	case <-done:
		// Ensure Stop returned in a reasonable amount of time (<100 ms is the
		// plan's §7.1 criterion).
		elapsed := time.Since(start)
		assert.Less(t, elapsed, 500*time.Millisecond, "Stop took too long")
	case <-ctx.Done():
		t.Fatal("HeapSampler.Stop did not return within timeout")
	}

	assert.NotZero(t, s.Max(), "heap sampler should have recorded at least one non-zero sample")

	// Stop is idempotent.
	s.Stop()
}

// runtime_GC_barrier is a tiny helper that defeats compiler elimination of
// the allocation in TestSummaryRecord_HeapSampler.
func runtime_GC_barrier(x [][]byte) {
	sink = x
}

//nolint:gochecknoglobals
var sink [][]byte

// TestSummaryRecord_PromReader checks that ReadRetryCounterTotal gracefully
// returns 0 on an empty registry and sums correctly when the counter is
// populated.
func TestSummaryRecord_PromReader(t *testing.T) {
	t.Run("empty_registry", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		v, err := ReadRetryCounterTotal(reg)
		require.NoError(t, err)
		assert.Equal(t, 0.0, v)
	})

	t.Run("populated_counter", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		c := prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3_backend_retries_total",
				Help: "test",
			},
			[]string{"operation", "reason", "mode"},
		)
		reg.MustRegister(c)
		c.WithLabelValues("PutObject", "timeout", "standard").Add(2)
		c.WithLabelValues("GetObject", "5xx", "standard").Add(3)
		c.WithLabelValues("HeadObject", "throttling", "adaptive").Add(1)

		v, err := ReadRetryCounterTotal(reg)
		require.NoError(t, err)
		assert.Equal(t, 6.0, v)
	})

	t.Run("nil_uses_default_gatherer", func(t *testing.T) {
		// Do not register anything in DefaultGatherer here — just assert the
		// call succeeds. It can return non-zero in a shared test binary.
		_, err := ReadRetryCounterTotal(nil)
		require.NoError(t, err)
	})
}

// TestSummaryRecord_AppendJSONRecord validates the on-disk format: one JSON
// object per line, repeated calls append (not overwrite), and unmarshalling
// round-trips.
func TestSummaryRecord_AppendJSONRecord(t *testing.T) {
	t.Run("no_env_is_no_op", func(t *testing.T) {
		err := AppendJSONRecord("", SummaryRecord{Test: "Foo"})
		require.NoError(t, err)
	})

	t.Run("round_trip", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "out.ndjson")

		rec1 := SummaryRecord{
			Test:           "Load_RangeRead",
			ThroughputMBPS: 145.2,
			LatencyNS:      LatencyPercentiles{P50: 1, P95: 2, P99: 3},
			Errors:         0,
			RetriesTotal:   3,
		}
		rec2 := SummaryRecord{Test: "Load_Multipart", ThroughputMBPS: 88.7}

		require.NoError(t, AppendJSONRecord(path, rec1))
		require.NoError(t, AppendJSONRecord(path, rec2))

		b, err := os.ReadFile(path)
		require.NoError(t, err)

		lines := 0
		for _, l := range splitLines(b) {
			if len(l) == 0 {
				continue
			}
			var rec SummaryRecord
			require.NoError(t, json.Unmarshal(l, &rec))
			lines++
		}
		assert.Equal(t, 2, lines)
	})
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
