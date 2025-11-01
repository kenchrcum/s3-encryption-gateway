package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all application metrics.
type Metrics struct {
	httpRequestsTotal     *prometheus.CounterVec
	httpRequestDuration   *prometheus.HistogramVec
	httpRequestBytes      *prometheus.CounterVec
	s3OperationsTotal     *prometheus.CounterVec
	s3OperationDuration   *prometheus.HistogramVec
	s3OperationErrors      *prometheus.CounterVec
}

// NewMetrics creates a new metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{
		httpRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),
		httpRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "path", "status"},
		),
		httpRequestBytes: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_request_bytes_total",
				Help: "Total bytes transferred in HTTP requests",
			},
			[]string{"method", "path"},
		),
		s3OperationsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3_operations_total",
				Help: "Total number of S3 operations",
			},
			[]string{"operation", "bucket"},
		),
		s3OperationDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "s3_operation_duration_seconds",
				Help:    "S3 operation duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"operation", "bucket"},
		),
		s3OperationErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3_operation_errors_total",
				Help: "Total number of S3 operation errors",
			},
			[]string{"operation", "bucket", "error_type"},
		),
	}
}

// RecordHTTPRequest records an HTTP request metric.
func (m *Metrics) RecordHTTPRequest(method, path string, status int, duration time.Duration, bytes int64) {
	m.httpRequestsTotal.WithLabelValues(method, path, http.StatusText(status)).Inc()
	m.httpRequestDuration.WithLabelValues(method, path, http.StatusText(status)).Observe(duration.Seconds())
	m.httpRequestBytes.WithLabelValues(method, path).Add(float64(bytes))
}

// RecordS3Operation records an S3 operation metric.
func (m *Metrics) RecordS3Operation(operation, bucket string, duration time.Duration) {
	m.s3OperationsTotal.WithLabelValues(operation, bucket).Inc()
	m.s3OperationDuration.WithLabelValues(operation, bucket).Observe(duration.Seconds())
}

// RecordS3Error records an S3 operation error.
func (m *Metrics) RecordS3Error(operation, bucket, errorType string) {
	m.s3OperationErrors.WithLabelValues(operation, bucket, errorType).Inc()
}

// Handler returns the HTTP handler for metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.Handler()
}