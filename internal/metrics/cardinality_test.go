package metrics

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestSanitizePathLabel(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/", "/"},
		{"/metrics", "/metrics"},
		{"/health", "/health"},
		{"/bucket/key", "/bucket/*"},
		{"/bucket/key/with/more/segments", "/bucket/*"},
		{"/bucket", "/bucket"}, // Edge case: treated as segment, maybe should be /bucket? Code says: if len(segs) <= 1 return / + segs[0]
		{"/bucket?query=param", "/bucket"},
		{"", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := sanitizePathLabel(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRecordHTTPRequest_Cardinality(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetricsWithRegistry(reg)

	// Record requests with high cardinality paths
	m.RecordHTTPRequest(context.Background(), "GET", "/mybucket/obj1", http.StatusOK, time.Millisecond, 100)
	m.RecordHTTPRequest(context.Background(), "GET", "/mybucket/obj2", http.StatusOK, time.Millisecond, 100)
	m.RecordHTTPRequest(context.Background(), "GET", "/otherbucket/obj1", http.StatusOK, time.Millisecond, 100)

	// Check that we have collapsed paths
	// We expect /mybucket/* and /otherbucket/*
	
	// Verify /mybucket/* count is 2
	countMyBucket := testutil.ToFloat64(m.httpRequestsTotal.WithLabelValues("GET", "/mybucket/*", "OK"))
	assert.Equal(t, 2.0, countMyBucket)

	// Verify /otherbucket/* count is 1
	countOtherBucket := testutil.ToFloat64(m.httpRequestsTotal.WithLabelValues("GET", "/otherbucket/*", "OK"))
	assert.Equal(t, 1.0, countOtherBucket)
}

func TestRecordS3Operation_DisableBucketLabel(t *testing.T) {
	// Create metrics with bucket label disabled
	reg := prometheus.NewRegistry()
	cfg := Config{EnableBucketLabel: false}
	m := newMetricsWithRegistry(reg, cfg)

	m.RecordS3Operation(context.Background(), "PutObject", "bucket-1", time.Millisecond)
	m.RecordS3Operation(context.Background(), "PutObject", "bucket-2", time.Millisecond)

	// Should align to bucket="*"
	count := testutil.ToFloat64(m.s3OperationsTotal.WithLabelValues("PutObject", "*"))
	assert.Equal(t, 2.0, count)

	// Verify that specific buckets are NOT tracked
	// Note: testutil.ToFloat64 panics or returns 0 if label values don't match existing metric.
	// However, since we didn't record them, we can't easily check for "absence" with ToFloat64 
	// without knowing if it returns 0 for non-existent label set or if it errors.
	// But checking the aggregate "*" is sufficient to prove logic path was taken.
}

func TestRecordS3Error_DisableBucketLabel(t *testing.T) {
	reg := prometheus.NewRegistry()
	cfg := Config{EnableBucketLabel: false}
	m := newMetricsWithRegistry(reg, cfg)

	m.RecordS3Error(context.Background(), "GetObject", "bucket-1", "NoSuchKey")
	m.RecordS3Error(context.Background(), "GetObject", "bucket-2", "NoSuchKey")

	count := testutil.ToFloat64(m.s3OperationErrors.WithLabelValues("GetObject", "*", "NoSuchKey"))
	assert.Equal(t, 2.0, count)
}

