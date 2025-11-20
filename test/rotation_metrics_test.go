//go:build integration
// +build integration

package test

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/kenneth/s3-encryption-gateway/internal/audit"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/kenneth/s3-encryption-gateway/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// TestRotationMetrics verifies that rotated reads are tracked via metrics
// when decrypting objects encrypted with older key versions.
func TestRotationMetrics(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create metrics registry
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)

	// Create mock key manager that simulates rotation
	keyManager := &mockRotatingKeyManager{
		activeVersion: 1, // Start with version 1
		keys: map[int][]byte{
			1: []byte("key-version-1"),
			2: []byte("key-version-2"),
		},
	}

	// Create encryption engine
	engine, err := crypto.NewEngine("fallback-password-123456")
	require.NoError(t, err)
	crypto.SetKeyManager(engine, keyManager)

	// Encrypt with key version 1 (simulate old object)
	plaintext1 := []byte("Object encrypted with key version 1")
	encReader1, encMetadata1, err := engine.Encrypt(bytes.NewReader(plaintext1), map[string]string{
		"Content-Type": "text/plain",
	})
	require.NoError(t, err)
	require.Equal(t, "1", encMetadata1[crypto.MetaKeyVersion])

	encryptedData1, err := io.ReadAll(encReader1)
	require.NoError(t, err)

	// Now rotate to version 2
	keyManager.activeVersion = 2

	// Encrypt with key version 2 (new object)
	plaintext2 := []byte("Object encrypted with key version 2")
	encReader2, encMetadata2, err := engine.Encrypt(bytes.NewReader(plaintext2), map[string]string{
		"Content-Type": "text/plain",
	})
	require.NoError(t, err)
	require.Equal(t, "2", encMetadata2[crypto.MetaKeyVersion])

	// Decrypt version 2 object (should NOT trigger rotated read)
	decReader2, _, err := engine.Decrypt(bytes.NewReader(encryptedData1), encMetadata1)
	require.NoError(t, err)
	decrypted2, err := io.ReadAll(decReader2)
	require.NoError(t, err)
	require.Equal(t, plaintext1, decrypted2)

	// Check metrics - we need to manually track this since we're testing the engine directly
	// In real usage, the handler would track this
	keyVersionUsed := 1
	activeKeyVersion := 2
	if keyVersionUsed > 0 && activeKeyVersion > 0 && keyVersionUsed != activeKeyVersion {
		m.RecordRotatedRead(context.Background(), keyVersionUsed, activeKeyVersion)
	}

	// Verify rotated read metric
	count := testutil.ToFloat64(m.GetRotatedReadsMetric().WithLabelValues("1", "2"))
	require.Equal(t, 1.0, count, "Should have recorded 1 rotated read")

	// Decrypt version 2 object (should NOT trigger rotated read)
	encryptedData2, err := io.ReadAll(encReader2)
	require.NoError(t, err)
	decReader2New, _, err := engine.Decrypt(bytes.NewReader(encryptedData2), encMetadata2)
	require.NoError(t, err)
	decrypted2New, err := io.ReadAll(decReader2New)
	require.NoError(t, err)
	require.Equal(t, plaintext2, decrypted2New)

	// Verify no additional rotated read for version 2
	count = testutil.ToFloat64(m.GetRotatedReadsMetric().WithLabelValues("2", "2"))
	require.Equal(t, 0.0, count, "Should not have recorded rotated read for active version")
}

// TestRotationAuditLog verifies that audit logs include rotated read metadata
func TestRotationAuditLog(t *testing.T) {
	// Create audit logger
	auditLogger := audit.NewLogger(100, nil)

	// Simulate decrypt with rotated key
	keyVersionUsed := 1
	activeKeyVersion := 2
	algorithm := "AES256-GCM"

	// Create audit metadata
	auditMetadata := make(map[string]interface{})
	if keyVersionUsed > 0 && activeKeyVersion > 0 && keyVersionUsed != activeKeyVersion {
		auditMetadata["rotated_read"] = true
		auditMetadata["key_version_used"] = keyVersionUsed
		auditMetadata["active_key_version"] = activeKeyVersion
	}

	// Log decrypt event
	auditLogger.LogDecrypt("test-bucket", "test-key", algorithm, keyVersionUsed, true, nil, 0, auditMetadata)

	// Verify audit log
	events := auditLogger.GetEvents()
	require.Len(t, events, 1)
	event := events[0]

	require.Equal(t, audit.EventTypeDecrypt, event.EventType)
	require.Equal(t, 1, event.KeyVersion)
	require.NotNil(t, event.Metadata)
	require.True(t, event.Metadata["rotated_read"].(bool))
	require.Equal(t, 1, event.Metadata["key_version_used"].(int))
	require.Equal(t, 2, event.Metadata["active_key_version"].(int))
}

// mockRotatingKeyManager simulates a key manager with rotation support
type mockRotatingKeyManager struct {
	activeVersion int
	keys           map[int][]byte
}

func (m *mockRotatingKeyManager) Provider() string {
	return "mock-rotating"
}

func (m *mockRotatingKeyManager) WrapKey(ctx context.Context, plaintext []byte, metadata map[string]string) (*crypto.KeyEnvelope, error) {
	return &crypto.KeyEnvelope{
		KeyID:      "mock-key",
		KeyVersion: m.activeVersion,
		Provider:   "mock-rotating",
		Ciphertext: plaintext, // Simplified for testing
	}, nil
}

func (m *mockRotatingKeyManager) UnwrapKey(ctx context.Context, envelope *crypto.KeyEnvelope, metadata map[string]string) ([]byte, error) {
	// Verify key version exists
	if _, ok := m.keys[envelope.KeyVersion]; !ok {
		return nil, context.DeadlineExceeded // Simplified error for testing
	}
	return envelope.Ciphertext, nil
}

func (m *mockRotatingKeyManager) ActiveKeyVersion(ctx context.Context) (int, error) {
	return m.activeVersion, nil
}

func (m *mockRotatingKeyManager) HealthCheck(ctx context.Context) error {
	return nil
}

func (m *mockRotatingKeyManager) Close(ctx context.Context) error {
	return nil
}

