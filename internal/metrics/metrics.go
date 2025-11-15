package metrics

import (
	"net/http"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
    "strings"
)

var (
	// defaultRegistry is the default Prometheus registry
	defaultRegistry = prometheus.DefaultRegisterer
)

// Metrics holds all application metrics.
type Metrics struct {
	httpRequestsTotal    *prometheus.CounterVec
	httpRequestDuration  *prometheus.HistogramVec
	httpRequestBytes     *prometheus.CounterVec
	s3OperationsTotal    *prometheus.CounterVec
	s3OperationDuration  *prometheus.HistogramVec
	s3OperationErrors    *prometheus.CounterVec
	encryptionOperations *prometheus.CounterVec
	encryptionDuration   *prometheus.HistogramVec
	encryptionErrors     *prometheus.CounterVec
	encryptionBytes      *prometheus.CounterVec
	bufferPoolHits       *prometheus.CounterVec
	bufferPoolMisses     *prometheus.CounterVec
	activeConnections    prometheus.Gauge
	goroutines           prometheus.Gauge
	memoryAllocBytes     prometheus.Gauge
	memorySysBytes       prometheus.Gauge
}

// NewMetrics creates a new metrics instance.
func NewMetrics() *Metrics {
	return newMetricsWithRegistry(defaultRegistry)
}

// NewMetricsWithRegistry creates a new metrics instance with a custom registry.
// This is useful for testing to avoid metric registration conflicts.
func NewMetricsWithRegistry(reg prometheus.Registerer) *Metrics {
	return newMetricsWithRegistry(reg)
}

// newMetricsWithRegistry creates a new metrics instance with a custom registry (for testing).
func newMetricsWithRegistry(reg prometheus.Registerer) *Metrics {
	factory := promauto.With(reg)
	return &Metrics{
		httpRequestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),
		httpRequestDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "path", "status"},
		),
		httpRequestBytes: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_request_bytes_total",
				Help: "Total bytes transferred in HTTP requests",
			},
			[]string{"method", "path"},
		),
		s3OperationsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3_operations_total",
				Help: "Total number of S3 operations",
			},
			[]string{"operation", "bucket"},
		),
		s3OperationDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "s3_operation_duration_seconds",
				Help:    "S3 operation duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"operation", "bucket"},
		),
		s3OperationErrors: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3_operation_errors_total",
				Help: "Total number of S3 operation errors",
			},
			[]string{"operation", "bucket", "error_type"},
		),
		encryptionOperations: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "encryption_operations_total",
				Help: "Total number of encryption/decryption operations",
			},
			[]string{"operation"}, // "encrypt" or "decrypt"
		),
		encryptionDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "encryption_duration_seconds",
				Help:    "Encryption/decryption operation duration in seconds",
				Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
			},
			[]string{"operation"},
		),
		encryptionErrors: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "encryption_errors_total",
				Help: "Total number of encryption/decryption errors",
			},
			[]string{"operation", "error_type"},
		),
		encryptionBytes: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "encryption_bytes_total",
				Help: "Total bytes encrypted/decrypted",
			},
			[]string{"operation"},
		),
		bufferPoolHits: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "buffer_pool_hits_total",
				Help: "Total number of buffer pool hits",
			},
			[]string{"size_class"},
		),
		bufferPoolMisses: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "buffer_pool_misses_total",
				Help: "Total number of buffer pool misses",
			},
			[]string{"size_class"},
		),
		activeConnections: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "active_connections",
				Help: "Number of active HTTP connections",
			},
		),
		goroutines: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "goroutines_total",
				Help: "Number of goroutines",
			},
		),
		memoryAllocBytes: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "memory_alloc_bytes",
				Help: "Number of bytes allocated and not yet freed",
			},
		),
		memorySysBytes: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "memory_sys_bytes",
				Help: "Total bytes of memory obtained from OS",
			},
		),
	}
}

// RecordHTTPRequest records an HTTP request metric.
func (m *Metrics) RecordHTTPRequest(method, path string, status int, duration time.Duration, bytes int64) {
    label := sanitizePathLabel(path)
    m.httpRequestsTotal.WithLabelValues(method, label, http.StatusText(status)).Inc()
    m.httpRequestDuration.WithLabelValues(method, label, http.StatusText(status)).Observe(duration.Seconds())
    m.httpRequestBytes.WithLabelValues(method, label).Add(float64(bytes))
}

// sanitizePathLabel reduces high-cardinality paths to stable labels.
// Examples:
// "/metrics" => "/metrics"
// "/bucket/key/long/path" => "/bucket/*"
func sanitizePathLabel(path string) string {
    if path == "" || path == "/" {
        return "/"
    }
    // Trim query if any (defensive; callers typically pass Path only)
    if i := strings.IndexByte(path, '?'); i >= 0 {
        path = path[:i]
    }
    // Split into segments
    segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
    if len(segs) <= 1 {
        return "/" + segs[0]
    }
    return "/" + segs[0] + "/*"
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

// RecordEncryptionOperation records an encryption operation metric.
func (m *Metrics) RecordEncryptionOperation(operation string, duration time.Duration, bytes int64) {
	m.encryptionOperations.WithLabelValues(operation).Inc()
	m.encryptionDuration.WithLabelValues(operation).Observe(duration.Seconds())
	m.encryptionBytes.WithLabelValues(operation).Add(float64(bytes))
}

// RecordEncryptionError records an encryption operation error.
func (m *Metrics) RecordEncryptionError(operation, errorType string) {
	m.encryptionErrors.WithLabelValues(operation, errorType).Inc()
}

// RecordBufferPoolHit records a buffer pool hit.
func (m *Metrics) RecordBufferPoolHit(sizeClass string) {
	m.bufferPoolHits.WithLabelValues(sizeClass).Inc()
}

// RecordBufferPoolMiss records a buffer pool miss.
func (m *Metrics) RecordBufferPoolMiss(sizeClass string) {
	m.bufferPoolMisses.WithLabelValues(sizeClass).Inc()
}

// UpdateSystemMetrics updates system-level metrics (goroutines, memory).
func (m *Metrics) UpdateSystemMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	m.goroutines.Set(float64(runtime.NumGoroutine()))
	m.memoryAllocBytes.Set(float64(memStats.Alloc))
	m.memorySysBytes.Set(float64(memStats.Sys))
}

// IncrementActiveConnections increments the active connections counter.
func (m *Metrics) IncrementActiveConnections() {
	m.activeConnections.Inc()
}

// DecrementActiveConnections decrements the active connections counter.
func (m *Metrics) DecrementActiveConnections() {
	m.activeConnections.Dec()
}

// StartSystemMetricsCollector starts a goroutine that periodically updates system metrics.
func (m *Metrics) StartSystemMetricsCollector() {
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for range ticker.C {
			m.UpdateSystemMetrics()
		}
	}()
}

// Handler returns the HTTP handler for metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.Handler()
}
