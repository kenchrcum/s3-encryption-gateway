package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordRotatedRead(t *testing.T) {
	// Create a new registry for testing
	reg := prometheus.NewRegistry()
	m := NewMetricsWithRegistry(reg)

	// Record rotated reads
	m.RecordRotatedRead(1, 2) // key version 1, active version 2
	m.RecordRotatedRead(1, 2) // same combination
	m.RecordRotatedRead(1, 3) // key version 1, active version 3
	m.RecordRotatedRead(2, 3) // key version 2, active version 3

	// Verify metrics
	count := testutil.ToFloat64(m.rotatedReads.WithLabelValues("1", "2"))
	assert.Equal(t, 2.0, count, "Should have 2 rotated reads for key_version=1, active_version=2")

	count = testutil.ToFloat64(m.rotatedReads.WithLabelValues("1", "3"))
	assert.Equal(t, 1.0, count, "Should have 1 rotated read for key_version=1, active_version=3")

	count = testutil.ToFloat64(m.rotatedReads.WithLabelValues("2", "3"))
	assert.Equal(t, 1.0, count, "Should have 1 rotated read for key_version=2, active_version=3")
}

func TestRecordRotatedRead_ZeroVersions(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetricsWithRegistry(reg)

	// Record with zero versions (should still work)
	m.RecordRotatedRead(0, 0)
	m.RecordRotatedRead(0, 1)

	count := testutil.ToFloat64(m.rotatedReads.WithLabelValues("0", "0"))
	assert.Equal(t, 1.0, count)

	count = testutil.ToFloat64(m.rotatedReads.WithLabelValues("0", "1"))
	assert.Equal(t, 1.0, count)
}

func TestRecordRotatedRead_MultipleCalls(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetricsWithRegistry(reg)

	// Record many rotated reads
	for i := 0; i < 100; i++ {
		m.RecordRotatedRead(1, 2)
	}

	count := testutil.ToFloat64(m.rotatedReads.WithLabelValues("1", "2"))
	assert.Equal(t, 100.0, count, "Should have 100 rotated reads")
}

func TestRotatedReadsMetric_Description(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetricsWithRegistry(reg)

	// Ensure metric is initialized by recording a zero value
	// This ensures it appears in Gather() even if unused (depending on client version/settings)
	m.RecordRotatedRead(0, 0)

	// Verify metric is registered
	metrics, err := reg.Gather()
	require.NoError(t, err)

		var found bool
		for _, metricFamily := range metrics {
			if metricFamily.GetName() == "kms_rotated_reads_total" {
				found = true
				assert.Equal(t, "Total number of decryption operations using rotated (non-active) key versions", metricFamily.GetHelp())
				// Verify it's a counter (has counter metrics)
				assert.Greater(t, len(metricFamily.GetMetric()), 0, "Should have at least one metric")
			}
		}
		assert.True(t, found, "kms_rotated_reads_total metric should be registered")
}

func TestRotatedReadsMetric_Labels(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetricsWithRegistry(reg)

	// Record with different label combinations
	m.RecordRotatedRead(1, 2)
	m.RecordRotatedRead(1, 3)
	m.RecordRotatedRead(2, 3)
	m.RecordRotatedRead(2, 4)

	// Verify all label combinations exist by checking metric values
	count1_2 := testutil.ToFloat64(m.rotatedReads.WithLabelValues("1", "2"))
	count1_3 := testutil.ToFloat64(m.rotatedReads.WithLabelValues("1", "3"))
	count2_3 := testutil.ToFloat64(m.rotatedReads.WithLabelValues("2", "3"))
	count2_4 := testutil.ToFloat64(m.rotatedReads.WithLabelValues("2", "4"))

	assert.Equal(t, 1.0, count1_2, "Should have recorded rotated read for key_version=1, active_version=2")
	assert.Equal(t, 1.0, count1_3, "Should have recorded rotated read for key_version=1, active_version=3")
	assert.Equal(t, 1.0, count2_3, "Should have recorded rotated read for key_version=2, active_version=3")
	assert.Equal(t, 1.0, count2_4, "Should have recorded rotated read for key_version=2, active_version=4")
}

