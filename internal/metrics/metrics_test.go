package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestNewMetrics(t *testing.T) {
	// Use a custom registry to avoid duplicate registration issues in tests
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})
	if m == nil {
		t.Fatal("NewMetrics returned nil")
	}

	if m.httpRequestsTotal == nil {
		t.Error("httpRequestsTotal is nil")
	}

	if m.httpRequestDuration == nil {
		t.Error("httpRequestDuration is nil")
	}

	if m.s3OperationsTotal == nil {
		t.Error("s3OperationsTotal is nil")
	}
}

func TestMetrics_RecordHTTPRequest(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})

	m.RecordHTTPRequest(context.Background(), "GET", "/test", http.StatusOK, 100*time.Millisecond, 1024)

	// Metrics are registered with prometheus, verify they don't panic
	// The actual metric values are tested through Prometheus endpoint
}

func TestMetrics_RecordS3Operation(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})

	m.RecordS3Operation(context.Background(), "PutObject", "test-bucket", 50*time.Millisecond)

	// Metrics are registered with prometheus, verify they don't panic
}

func TestMetrics_RecordS3Error(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})

	m.RecordS3Error(context.Background(), "GetObject", "test-bucket", "NoSuchKey")

	// Metrics are registered with prometheus, verify they don't panic
}

func TestMetrics_Handler(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})
	
	// Record some metrics first so they appear in output
	m.RecordHTTPRequest(context.Background(), "GET", "/test", http.StatusOK, 100*time.Millisecond, 1024)
	m.RecordS3Operation(context.Background(), "PutObject", "test-bucket", 50*time.Millisecond)

	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})

	if handler == nil {
		t.Fatal("Handler returned nil")
	}

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify metrics endpoint returns prometheus format
	body := w.Body.String()
	if len(body) == 0 {
		t.Error("metrics endpoint returned empty body")
	}

	// Check for some expected prometheus metric names
	expectedMetrics := []string{
		"http_requests_total",
		"s3_operations_total",
	}
	for _, metric := range expectedMetrics {
		if !contains(body, metric) {
			t.Errorf("expected metrics output to contain %q", metric)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}