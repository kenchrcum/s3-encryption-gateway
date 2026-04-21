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
	config                            Config
	httpRequestsTotal                 *prometheus.CounterVec
	httpRequestDuration               *prometheus.HistogramVec
	httpRequestBytes                  *prometheus.CounterVec
	s3OperationsTotal                 *prometheus.CounterVec
	s3OperationDuration               *prometheus.HistogramVec
	s3OperationErrors                 *prometheus.CounterVec
	encryptionOperations              *prometheus.CounterVec
	encryptionDuration                *prometheus.HistogramVec
	encryptionErrors                  *prometheus.CounterVec
	encryptionBytes                   *prometheus.CounterVec
	rotatedReads                      *prometheus.CounterVec
	bufferPoolHits                    *prometheus.CounterVec
	bufferPoolMisses                  *prometheus.CounterVec
	activeConnections                 prometheus.Gauge
	goroutines                        prometheus.Gauge
	memoryAllocBytes                  prometheus.Gauge
	memorySysBytes                    prometheus.Gauge
	hardwareAccelerationEnabled       *prometheus.GaugeVec
	fipsMode                          prometheus.Gauge
	uploadPartCopyTotal               *prometheus.CounterVec
	uploadPartCopyBytes               *prometheus.CounterVec
	uploadPartCopyDuration            *prometheus.HistogramVec
	uploadPartCopyLegacyFallbackTotal prometheus.Counter
	// Admin and rotation metrics
	kmsActiveKeyVersion      *prometheus.GaugeVec
	kmsRotationOpsTotal      *prometheus.CounterVec
	kmsRotationDuration      *prometheus.HistogramVec
	kmsRotationInFlightWraps prometheus.Gauge
	gatewayAdminAPIEnabled   prometheus.Gauge

	// V0.6-S3-2 — objects skipped by the key-rotation worker because
	// they are Object-Lock-protected at the backend. See ADR 0008.
	gatewayRotationSkippedLocked *prometheus.CounterVec

	// V0.6-SEC-3 — encrypted multipart upload metrics (ADR 0009).
	mpuEncryptedTotal    *prometheus.CounterVec
	mpuPartsTotal        *prometheus.CounterVec
	mpuStateStoreOps     *prometheus.CounterVec
	mpuStateStoreLatency *prometheus.HistogramVec
	mpuValkeyUp          prometheus.Gauge
	mpuValkeyInsecure    prometheus.Gauge
	mpuManifestBytes     prometheus.Histogram
	mpuManifestStorage   *prometheus.CounterVec
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
		fipsMode: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "gateway_fips_mode",
				Help: "FIPS 140-3 mode status (1=enabled, 0=disabled)",
			},
		),
		uploadPartCopyTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_upload_part_copy_total",
				Help: "Total number of UploadPartCopy operations, labelled by source encryption mode and result",
			},
			[]string{"source_mode", "result"}, // source_mode ∈ {chunked,legacy,plaintext}; result ∈ {ok,error}
		),
		uploadPartCopyBytes: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_upload_part_copy_bytes_total",
				Help: "Total plaintext bytes copied via UploadPartCopy, labelled by source encryption mode",
			},
			[]string{"source_mode"},
		),
		uploadPartCopyDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gateway_upload_part_copy_duration_seconds",
				Help:    "UploadPartCopy operation duration in seconds, labelled by source encryption mode",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"source_mode"},
		),
		uploadPartCopyLegacyFallbackTotal: factory.NewCounter(
			prometheus.CounterOpts{
				Name: "gateway_upload_part_copy_legacy_fallback_total",
				Help: "Total number of UploadPartCopy operations that used the legacy (full-object-buffer) fallback path",
			},
		),
		kmsActiveKeyVersion: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kms_active_key_version",
				Help: "Currently active KMS key version per provider",
			},
			[]string{"provider"},
		),
		kmsRotationOpsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kms_rotation_operations_total",
				Help: "Total number of key rotation operations by step and result",
			},
			[]string{"step", "result"},
		),
		kmsRotationDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "kms_rotation_duration_seconds",
				Help:    "Duration of key rotation operations by step",
				Buckets: []float64{0.001, 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30},
			},
			[]string{"step"},
		),
		kmsRotationInFlightWraps: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "kms_rotation_in_flight_wraps",
				Help: "Number of in-flight WrapKey operations during rotation drain",
			},
		),
		gatewayAdminAPIEnabled: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "gateway_admin_api_enabled",
				Help: "Whether the admin API listener is enabled (1=enabled, 0=disabled)",
			},
		),
		gatewayRotationSkippedLocked: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_rotation_skipped_locked_total",
				Help: "Objects skipped during key rotation because they are Object-Lock-protected at the backend (labelled by mode: COMPLIANCE, GOVERNANCE, LEGAL_HOLD).",
			},
			[]string{"mode"},
		),

		// V0.6-SEC-3 MPU metrics.
		mpuEncryptedTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_mpu_encrypted_total",
				Help: "Total encrypted multipart uploads completed (result=success|error).",
			},
			[]string{"result"},
		),
		mpuPartsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_mpu_parts_total",
				Help: "Total encrypted multipart parts uploaded (result=success|error).",
			},
			[]string{"result"},
		),
		mpuStateStoreOps: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_mpu_state_store_ops_total",
				Help: "Total Valkey state store operations (op=create|append|get|delete|healthcheck; result=success|error).",
			},
			[]string{"op", "result"},
		),
		mpuStateStoreLatency: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gateway_mpu_state_store_latency_seconds",
				Help:    "Latency of Valkey state store operations in seconds.",
				Buckets: []float64{0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5},
			},
			[]string{"op"},
		),
		mpuValkeyUp: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "gateway_mpu_valkey_up",
				Help: "1 if the last Valkey health check succeeded, 0 otherwise.",
			},
		),
		mpuValkeyInsecure: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "gateway_mpu_valkey_insecure",
				Help: "1 if the gateway was started with insecure_allow_plaintext=true for Valkey.",
			},
		),
		mpuManifestBytes: factory.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "gateway_mpu_manifest_bytes",
				Help:    "Size of serialised MPU manifests in bytes.",
				Buckets: []float64{256, 512, 1024, 1800, 4096, 16384},
			},
		),
		mpuManifestStorage: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_mpu_manifest_storage_total",
				Help: "MPU manifests by storage location (location=inline|fallback).",
			},
			[]string{"location"},
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

// SetFIPSMode sets the FIPS 140-3 mode status metric.
func (m *Metrics) SetFIPSMode(enabled bool) {
	val := 0.0
	if enabled {
		val = 1.0
	}
	m.fipsMode.Set(val)
}

// GetHardwareAccelerationEnabledMetric returns the hardware acceleration enabled metric (for testing).
func (m *Metrics) GetHardwareAccelerationEnabledMetric() *prometheus.GaugeVec {
	return m.hardwareAccelerationEnabled
}

// SetActiveKeyVersion sets the active KMS key version gauge.
func (m *Metrics) SetActiveKeyVersion(provider string, version int) {
	m.kmsActiveKeyVersion.WithLabelValues(provider).Set(float64(version))
}

// RecordRotationOperation records a rotation operation counter and duration.
func (m *Metrics) RecordRotationOperation(step, result string, duration time.Duration) {
	m.kmsRotationOpsTotal.WithLabelValues(step, result).Inc()
	m.kmsRotationDuration.WithLabelValues(step).Observe(duration.Seconds())
}

// SetRotationInFlightWraps sets the in-flight wraps gauge.
func (m *Metrics) SetRotationInFlightWraps(count int64) {
	m.kmsRotationInFlightWraps.Set(float64(count))
}

// SetAdminAPIEnabled sets the admin API enabled gauge.
func (m *Metrics) SetAdminAPIEnabled(enabled bool) {
	val := 0.0
	if enabled {
		val = 1.0
	}
	m.gatewayAdminAPIEnabled.Set(val)
}

// RecordRotationSkippedLocked records that a key-rotation attempt
// skipped an object because it is Object-Lock-protected at the backend.
// mode should be one of "COMPLIANCE", "GOVERNANCE", or "LEGAL_HOLD".
// V0.6-S3-2 — see ADR 0008.
func (m *Metrics) RecordRotationSkippedLocked(mode string) {
	if m == nil || m.gatewayRotationSkippedLocked == nil {
		return
	}
	m.gatewayRotationSkippedLocked.WithLabelValues(mode).Inc()
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

// RecordUploadPartCopy records an UploadPartCopy operation.
// sourceMode MUST be one of "chunked", "legacy", "plaintext" (to keep label
// cardinality bounded). result MUST be "ok" or "error". bytesCopied is the
// number of plaintext bytes transferred into the destination part (0 on
// error). A single call emits to the total, bytes, and duration metrics; if
// sourceMode == "legacy" the legacy_fallback counter is also incremented.
func (m *Metrics) RecordUploadPartCopy(sourceMode, result string, bytesCopied int64, duration time.Duration) {
	m.uploadPartCopyTotal.WithLabelValues(sourceMode, result).Inc()
	m.uploadPartCopyDuration.WithLabelValues(sourceMode).Observe(duration.Seconds())
	if bytesCopied > 0 {
		m.uploadPartCopyBytes.WithLabelValues(sourceMode).Add(float64(bytesCopied))
	}
	if sourceMode == "legacy" {
		m.uploadPartCopyLegacyFallbackTotal.Inc()
	}
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

// RecordMPUEncrypted increments the gateway_mpu_encrypted_total counter.
func (m *Metrics) RecordMPUEncrypted(result string) {
	if m == nil || m.mpuEncryptedTotal == nil {
		return
	}
	m.mpuEncryptedTotal.WithLabelValues(result).Inc()
}

// RecordMPUPart increments the gateway_mpu_parts_total counter.
func (m *Metrics) RecordMPUPart(result string) {
	if m == nil || m.mpuPartsTotal == nil {
		return
	}
	m.mpuPartsTotal.WithLabelValues(result).Inc()
}

// RecordMPUStateStoreOp records a Valkey state store operation.
func (m *Metrics) RecordMPUStateStoreOp(op, result string, duration time.Duration) {
	if m == nil {
		return
	}
	if m.mpuStateStoreOps != nil {
		m.mpuStateStoreOps.WithLabelValues(op, result).Inc()
	}
	if m.mpuStateStoreLatency != nil {
		m.mpuStateStoreLatency.WithLabelValues(op).Observe(duration.Seconds())
	}
}

// SetMPUValkeyUp sets the gateway_mpu_valkey_up gauge.
func (m *Metrics) SetMPUValkeyUp(up bool) {
	if m == nil || m.mpuValkeyUp == nil {
		return
	}
	if up {
		m.mpuValkeyUp.Set(1)
	} else {
		m.mpuValkeyUp.Set(0)
	}
}

// SetMPUValkeyInsecure sets the gateway_mpu_valkey_insecure gauge.
func (m *Metrics) SetMPUValkeyInsecure(insecure bool) {
	if m == nil || m.mpuValkeyInsecure == nil {
		return
	}
	if insecure {
		m.mpuValkeyInsecure.Set(1)
	} else {
		m.mpuValkeyInsecure.Set(0)
	}
}

// ObserveMPUManifestBytes records manifest serialised size.
func (m *Metrics) ObserveMPUManifestBytes(n int) {
	if m == nil || m.mpuManifestBytes == nil {
		return
	}
	m.mpuManifestBytes.Observe(float64(n))
}

// RecordMPUManifestStorage increments the manifest storage location counter.
func (m *Metrics) RecordMPUManifestStorage(location string) {
	if m == nil || m.mpuManifestStorage == nil {
		return
	}
	m.mpuManifestStorage.WithLabelValues(location).Inc()
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
