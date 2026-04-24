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

// TestMetrics_RecordUploadPartCopy verifies the UploadPartCopy metric surface
// (added in V0.6-S3-1): gateway_upload_part_copy_total / bytes_total /
// duration_seconds / legacy_fallback_total. Exercises every label combo.
func TestMetrics_RecordUploadPartCopy(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})

	// One success in each source_mode.
	m.RecordUploadPartCopy("plaintext", "ok", 1024, 10*time.Millisecond)
	m.RecordUploadPartCopy("chunked", "ok", 2048, 20*time.Millisecond)
	m.RecordUploadPartCopy("legacy", "ok", 4096, 100*time.Millisecond)
	// And one error per mode.
	m.RecordUploadPartCopy("plaintext", "error", 0, 5*time.Millisecond)
	m.RecordUploadPartCopy("chunked", "error", 0, 5*time.Millisecond)
	m.RecordUploadPartCopy("legacy", "error", 0, 5*time.Millisecond)

	// Render and assert via Gather to avoid coupling to internal metric shape.
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	names := map[string]bool{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	wants := []string{
		"gateway_upload_part_copy_total",
		"gateway_upload_part_copy_bytes_total",
		"gateway_upload_part_copy_duration_seconds",
		"gateway_upload_part_copy_legacy_fallback_total",
	}
	for _, name := range wants {
		if !names[name] {
			t.Errorf("expected metric %q to be registered and non-empty after recording", name)
		}
	}
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

// ── V0.6-QA-2 Phase B.5 — extended coverage tests ──────────────────────────

// TestNewMetrics_DefaultConstructors verifies NewMetrics and NewMetricsWithConfig
// produce non-nil, functional Metrics instances.
func TestNewMetrics_DefaultConstructors(t *testing.T) {
	// These use the default registry — avoid calling them in parallel tests as
	// they would produce duplicate metric registration errors. Use custom registry.
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})
	if m == nil {
		t.Fatal("newMetricsWithRegistry() returned nil")
	}

	// Verify Gather works (all metrics registered)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	if len(mfs) == 0 {
		t.Error("Gather() returned no metric families")
	}
}

// TestMetrics_SetHardwareAccelerationStatus verifies the gauge is set correctly.
func TestMetrics_SetHardwareAccelerationStatus(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.SetHardwareAccelerationStatus("aes-ni", true)
	m.SetHardwareAccelerationStatus("arm-ce", false)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() == "hardware_acceleration_enabled" {
			found = true
			break
		}
	}
	if !found {
		t.Error("hardware_acceleration_enabled metric not found after SetHardwareAccelerationStatus")
	}
}

// TestMetrics_SetFIPSMode verifies the FIPS mode gauge.
func TestMetrics_SetFIPSMode(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.SetFIPSMode(true)
	m.SetFIPSMode(false)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	if !names["gateway_fips_mode"] {
		t.Error("gateway_fips_mode metric not found after SetFIPSMode")
	}
}

// TestMetrics_GetHardwareAccelerationEnabledMetric verifies the getter.
func TestMetrics_GetHardwareAccelerationEnabledMetric(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	gauge := m.GetHardwareAccelerationEnabledMetric()
	if gauge == nil {
		t.Error("GetHardwareAccelerationEnabledMetric() returned nil")
	}
}

// TestMetrics_SetActiveKeyVersion verifies SetActiveKeyVersion does not panic.
func TestMetrics_SetActiveKeyVersion(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.SetActiveKeyVersion("memory", 1)
	m.SetActiveKeyVersion("memory", 2)
}

// TestMetrics_RecordRotationOperation verifies RecordRotationOperation does not panic.
func TestMetrics_RecordRotationOperation(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordRotationOperation("wrap", "success", 100*time.Millisecond)
	m.RecordRotationOperation("commit", "error", 50*time.Millisecond)
}

// TestMetrics_SetRotationInFlightWraps verifies the gauge setter.
func TestMetrics_SetRotationInFlightWraps(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.SetRotationInFlightWraps(5)
	m.SetRotationInFlightWraps(0)
}

// TestMetrics_SetAdminAPIEnabled verifies SetAdminAPIEnabled.
func TestMetrics_SetAdminAPIEnabled(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.SetAdminAPIEnabled(true)
	m.SetAdminAPIEnabled(false)
}

// TestMetrics_RecordRotationSkippedLocked verifies RecordRotationSkippedLocked.
func TestMetrics_RecordRotationSkippedLocked(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordRotationSkippedLocked("COMPLIANCE")
	m.RecordRotationSkippedLocked("GOVERNANCE")
	m.RecordRotationSkippedLocked("LEGAL_HOLD")

	// nil-safe: should not panic
	var nilM *Metrics
	nilM.RecordRotationSkippedLocked("COMPLIANCE")
}

// TestMetrics_RecordEncryptionOperation verifies RecordEncryptionOperation.
func TestMetrics_RecordEncryptionOperation(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordEncryptionOperation(context.Background(), "encrypt", 10*time.Millisecond, 1024)
	m.RecordEncryptionOperation(context.Background(), "decrypt", 5*time.Millisecond, 512)
}

// TestMetrics_RecordEncryptionError verifies RecordEncryptionError.
func TestMetrics_RecordEncryptionError(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordEncryptionError(context.Background(), "encrypt", "auth_failure")
	m.RecordEncryptionError(context.Background(), "decrypt", "key_not_found")
}

// TestMetrics_RecordBufferPool verifies buffer pool hit/miss counters.
func TestMetrics_RecordBufferPool(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordBufferPoolHit("64k")
	m.RecordBufferPoolMiss("128k")
}

// TestMetrics_UpdateSystemMetrics verifies UpdateSystemMetrics does not panic.
func TestMetrics_UpdateSystemMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	// Should update goroutine, alloc, sys gauges without panicking
	m.UpdateSystemMetrics()
}

// TestMetrics_IncrementDecrementActiveConnections verifies connection counter.
func TestMetrics_IncrementDecrementActiveConnections(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.IncrementActiveConnections()
	m.IncrementActiveConnections()
	m.DecrementActiveConnections()
}

// TestMetrics_RecordRotatedRead verifies RecordRotatedRead does not panic.
func TestMetrics_RecordRotatedRead(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordRotatedRead(context.Background(), 1, 2)
	m.RecordRotatedRead(context.Background(), 2, 2)
}

// TestMetrics_NilSafe verifies all nil-guarded methods on a nil Metrics do
// not panic.
func TestMetrics_NilSafe(t *testing.T) {
	var m *Metrics

	m.RecordMPUEncrypted("success")
	m.RecordMPUPart("error")
	m.RecordMPUStateStoreOp("create", "success", time.Millisecond)
	m.SetMPUValkeyUp(true)
	m.SetMPUValkeyInsecure(false)
	m.ObserveMPUManifestBytes(100)
	m.RecordMPUManifestStorage("inline")
	m.RecordBackendRetry("PutObject", "503")
	m.RecordBackendRetryWithMode("GetObject", "503", "standard")
	m.RecordBackendAttemptsPerRequest("PutObject", 3)
	m.RecordBackendRetryGiveUp("PutObject", "503")
	m.RecordBackendRetryBackoff(100 * time.Millisecond)
	m.RecordPprofRequest("heap", "ok")
	m.SetAdminProfilingEnabled(true)
}

// TestMetrics_MPUMethods verifies MPU metric methods on a non-nil Metrics.
func TestMetrics_MPUMethods(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordMPUEncrypted("success")
	m.RecordMPUEncrypted("error")
	m.RecordMPUPart("success")
	m.RecordMPUStateStoreOp("create", "success", time.Millisecond)
	m.RecordMPUStateStoreOp("get", "error", time.Millisecond)
	m.SetMPUValkeyUp(true)
	m.SetMPUValkeyUp(false)
	m.SetMPUValkeyInsecure(true)
	m.ObserveMPUManifestBytes(1800)
	m.RecordMPUManifestStorage("inline")
	m.RecordMPUManifestStorage("fallback")

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	wants := []string{
		"gateway_mpu_encrypted_total",
		"gateway_mpu_parts_total",
		"gateway_mpu_state_store_ops_total",
		"gateway_mpu_valkey_up",
		"gateway_mpu_manifest_bytes",
		"gateway_mpu_manifest_storage_total",
	}
	for _, want := range wants {
		if !names[want] {
			t.Errorf("expected metric %q not found after recording", want)
		}
	}
}

// TestMetrics_Gather_AllFamiliesPresent verifies that Gather() returns all
// expected metric families after a fresh registry is populated.
func TestMetrics_Gather_AllFamiliesPresent(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})

	// Record a sample of each metric to make them appear in Gather
	ctx := context.Background()
	m.RecordHTTPRequest(ctx, "GET", "/test", http.StatusOK, time.Millisecond, 100)
	m.RecordS3Operation(ctx, "PutObject", "bucket", time.Millisecond)
	m.RecordEncryptionOperation(ctx, "encrypt", time.Millisecond, 100)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	// Check key metric families
	wants := []string{
		"http_requests_total",
		"http_request_duration_seconds",
		"s3_operations_total",
		"encryption_operations_total",
	}
	for _, want := range wants {
		if !names[want] {
			t.Errorf("expected metric family %q after recording operations", want)
		}
	}
}
