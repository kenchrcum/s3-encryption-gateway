package metrics

import (
	"context"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/trace"
)

var (
	// defaultRegistry is the default Prometheus registry
	defaultRegistry = prometheus.DefaultRegisterer
)

// Config holds metrics configuration.
type Config struct {
	EnableBucketLabel bool
}

// Metrics holds all application metrics.
type Metrics struct {
	config               Config
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
	rotatedReads         *prometheus.CounterVec
	bufferPoolHits       *prometheus.CounterVec
	bufferPoolMisses     *prometheus.CounterVec
	activeConnections    prometheus.Gauge
	goroutines           prometheus.Gauge
	memoryAllocBytes     prometheus.Gauge
	memorySysBytes       prometheus.Gauge
	hardwareAccelerationEnabled *prometheus.GaugeVec
}

// NewMetrics creates a new metrics instance with default configuration.
func NewMetrics() *Metrics {
	return NewMetricsWithConfig(Config{EnableBucketLabel: true})
}

// NewMetricsWithConfig creates a new metrics instance with the provided configuration.
func NewMetricsWithConfig(cfg Config) *Metrics {
	return newMetricsWithRegistry(defaultRegistry, cfg)
}

// NewMetricsWithRegistry creates a new metrics instance with a custom registry.
// This is useful for testing to avoid metric registration conflicts.
func NewMetricsWithRegistry(reg prometheus.Registerer) *Metrics {
	return newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})
}

// newMetricsWithRegistry creates a new metrics instance with a custom registry (for testing).
func newMetricsWithRegistry(reg prometheus.Registerer, cfg Config) *Metrics {
	factory := promauto.With(reg)
	return &Metrics{
		config: cfg,
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
		rotatedReads: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kms_rotated_reads_total",
				Help: "Total number of decryption operations using rotated (non-active) key versions",
			},
			[]string{"key_version", "active_version"},
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
		hardwareAccelerationEnabled: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "hardware_acceleration_enabled",
				Help: "Hardware acceleration status (1=enabled, 0=disabled)",
			},
			[]string{"type"},
		),
	}
}

// SetHardwareAccelerationStatus sets the hardware acceleration status metric.
func (m *Metrics) SetHardwareAccelerationStatus(accelType string, enabled bool) {
	val := 0.0
	if enabled {
		val = 1.0
	}
	m.hardwareAccelerationEnabled.WithLabelValues(accelType).Set(val)
}

// GetHardwareAccelerationEnabledMetric returns the hardware acceleration enabled metric (for testing).
func (m *Metrics) GetHardwareAccelerationEnabledMetric() *prometheus.GaugeVec {
	return m.hardwareAccelerationEnabled
}

// GetRotatedReadsMetric returns the rotated reads metric (for testing).
func (m *Metrics) GetRotatedReadsMetric() *prometheus.CounterVec {
	return m.rotatedReads
}

// RecordHTTPRequest records an HTTP request metric.
func (m *Metrics) RecordHTTPRequest(ctx context.Context, method, path string, status int, duration time.Duration, bytes int64) {
	label := sanitizePathLabel(path)
	labels := prometheus.Labels{"method": method, "path": label, "status": http.StatusText(status)}
	
	if exemplar := getExemplar(ctx); exemplar != nil {
		if adder, ok := m.httpRequestsTotal.With(labels).(prometheus.ExemplarAdder); ok {
			adder.AddWithExemplar(1, exemplar)
		} else {
			m.httpRequestsTotal.With(labels).Inc()
		}
		
		if observer, ok := m.httpRequestDuration.With(labels).(prometheus.ExemplarObserver); ok {
			observer.ObserveWithExemplar(duration.Seconds(), exemplar)
		} else {
			m.httpRequestDuration.With(labels).Observe(duration.Seconds())
		}
	} else {
		m.httpRequestsTotal.With(labels).Inc()
		m.httpRequestDuration.With(labels).Observe(duration.Seconds())
	}
	
	// No exemplars for byte counters usually
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
func (m *Metrics) RecordS3Operation(ctx context.Context, operation, bucket string, duration time.Duration) {
	bucketLabel := bucket
	if !m.config.EnableBucketLabel {
		bucketLabel = "*"
	}

	if exemplar := getExemplar(ctx); exemplar != nil {
		if adder, ok := m.s3OperationsTotal.WithLabelValues(operation, bucketLabel).(prometheus.ExemplarAdder); ok {
			adder.AddWithExemplar(1, exemplar)
		} else {
			m.s3OperationsTotal.WithLabelValues(operation, bucketLabel).Inc()
		}

		if observer, ok := m.s3OperationDuration.WithLabelValues(operation, bucketLabel).(prometheus.ExemplarObserver); ok {
			observer.ObserveWithExemplar(duration.Seconds(), exemplar)
		} else {
			m.s3OperationDuration.WithLabelValues(operation, bucketLabel).Observe(duration.Seconds())
		}
	} else {
		m.s3OperationsTotal.WithLabelValues(operation, bucketLabel).Inc()
		m.s3OperationDuration.WithLabelValues(operation, bucketLabel).Observe(duration.Seconds())
	}
}

// RecordS3Error records an S3 operation error.
func (m *Metrics) RecordS3Error(ctx context.Context, operation, bucket, errorType string) {
	bucketLabel := bucket
	if !m.config.EnableBucketLabel {
		bucketLabel = "*"
	}

	if exemplar := getExemplar(ctx); exemplar != nil {
		if adder, ok := m.s3OperationErrors.WithLabelValues(operation, bucketLabel, errorType).(prometheus.ExemplarAdder); ok {
			adder.AddWithExemplar(1, exemplar)
		} else {
			m.s3OperationErrors.WithLabelValues(operation, bucketLabel, errorType).Inc()
		}
	} else {
		m.s3OperationErrors.WithLabelValues(operation, bucketLabel, errorType).Inc()
	}
}

// RecordEncryptionOperation records an encryption operation metric.
func (m *Metrics) RecordEncryptionOperation(ctx context.Context, operation string, duration time.Duration, bytes int64) {
	if exemplar := getExemplar(ctx); exemplar != nil {
		if adder, ok := m.encryptionOperations.WithLabelValues(operation).(prometheus.ExemplarAdder); ok {
			adder.AddWithExemplar(1, exemplar)
		} else {
			m.encryptionOperations.WithLabelValues(operation).Inc()
		}

		if observer, ok := m.encryptionDuration.WithLabelValues(operation).(prometheus.ExemplarObserver); ok {
			observer.ObserveWithExemplar(duration.Seconds(), exemplar)
		} else {
			m.encryptionDuration.WithLabelValues(operation).Observe(duration.Seconds())
		}
	} else {
		m.encryptionOperations.WithLabelValues(operation).Inc()
		m.encryptionDuration.WithLabelValues(operation).Observe(duration.Seconds())
	}
	
	m.encryptionBytes.WithLabelValues(operation).Add(float64(bytes))
}

// RecordEncryptionError records an encryption operation error.
func (m *Metrics) RecordEncryptionError(ctx context.Context, operation, errorType string) {
	if exemplar := getExemplar(ctx); exemplar != nil {
		if adder, ok := m.encryptionErrors.WithLabelValues(operation, errorType).(prometheus.ExemplarAdder); ok {
			adder.AddWithExemplar(1, exemplar)
		} else {
			m.encryptionErrors.WithLabelValues(operation, errorType).Inc()
		}
	} else {
		m.encryptionErrors.WithLabelValues(operation, errorType).Inc()
	}
}

// RecordRotatedRead records a decryption operation using a rotated (non-active) key version.
func (m *Metrics) RecordRotatedRead(ctx context.Context, keyVersion, activeVersion int) {
	if exemplar := getExemplar(ctx); exemplar != nil {
		if adder, ok := m.rotatedReads.WithLabelValues(strconv.Itoa(keyVersion), strconv.Itoa(activeVersion)).(prometheus.ExemplarAdder); ok {
			adder.AddWithExemplar(1, exemplar)
		} else {
			m.rotatedReads.WithLabelValues(strconv.Itoa(keyVersion), strconv.Itoa(activeVersion)).Inc()
		}
	} else {
		m.rotatedReads.WithLabelValues(
			strconv.Itoa(keyVersion),
			strconv.Itoa(activeVersion),
		).Inc()
	}
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

// getExemplar extracts trace ID from context and returns prometheus Labels for exemplar.
func getExemplar(ctx context.Context) prometheus.Labels {
	if ctx == nil {
		return nil
	}
	spanContext := trace.SpanFromContext(ctx).SpanContext()
	if spanContext.IsValid() {
		return prometheus.Labels{"trace_id": spanContext.TraceID().String()}
	}
	return nil
}
