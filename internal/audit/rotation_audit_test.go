// Package audit — tier-1 unit tests for rotation audit-log metadata.
//
// Promoted from test/rotation_metrics_test.go (was //go:build integration).
// No Docker or external dependencies.
package audit

import (
	"testing"
)

// TestRotationAuditLog verifies that when a decrypt operation uses a rotated
// (non-active) key version, the audit log entry carries the expected metadata.
func TestRotationAuditLog(t *testing.T) {
	auditLogger := NewLogger(100, nil)

	keyVersionUsed := 1
	activeKeyVersion := 2
	algorithm := "AES256-GCM"

	auditMetadata := make(map[string]interface{})
	if keyVersionUsed > 0 && activeKeyVersion > 0 && keyVersionUsed != activeKeyVersion {
		auditMetadata["rotated_read"] = true
		auditMetadata["key_version_used"] = keyVersionUsed
		auditMetadata["active_key_version"] = activeKeyVersion
	}

	auditLogger.LogDecrypt("test-bucket", "test-key", algorithm, keyVersionUsed, true, nil, 0, auditMetadata)

	events := auditLogger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	ev := events[0]

	if ev.EventType != EventTypeDecrypt {
		t.Errorf("EventType = %q, want %q", ev.EventType, EventTypeDecrypt)
	}
	if ev.KeyVersion != 1 {
		t.Errorf("KeyVersion = %d, want 1", ev.KeyVersion)
	}
	if ev.Metadata == nil {
		t.Fatal("Metadata must not be nil for a rotated-read event")
	}
	if v, ok := ev.Metadata["rotated_read"].(bool); !ok || !v {
		t.Errorf("Metadata[rotated_read] = %v, want true", ev.Metadata["rotated_read"])
	}
	if v, ok := ev.Metadata["key_version_used"].(int); !ok || v != 1 {
		t.Errorf("Metadata[key_version_used] = %v, want 1", ev.Metadata["key_version_used"])
	}
	if v, ok := ev.Metadata["active_key_version"].(int); !ok || v != 2 {
		t.Errorf("Metadata[active_key_version] = %v, want 2", ev.Metadata["active_key_version"])
	}
}
