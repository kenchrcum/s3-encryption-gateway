package audit

import (
	"testing"
	"time"
)

func TestAuditLogger_LogEncrypt(t *testing.T) {
	logger := NewLogger(100, nil)
	
	logger.LogEncrypt("test-bucket", "test-key", "AES256-GCM", 1, true, nil, 100*time.Millisecond, nil)
	
	events := logger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	
	event := events[0]
	if event.EventType != EventTypeEncrypt {
		t.Fatalf("expected event type %s, got %s", EventTypeEncrypt, event.EventType)
	}
	
	if event.Bucket != "test-bucket" {
		t.Fatalf("expected bucket test-bucket, got %s", event.Bucket)
	}
	
	if event.Key != "test-key" {
		t.Fatalf("expected key test-key, got %s", event.Key)
	}
	
	if !event.Success {
		t.Fatal("expected success to be true")
	}
}

func TestAuditLogger_LogDecrypt(t *testing.T) {
	logger := NewLogger(100, nil)
	
	logger.LogDecrypt("test-bucket", "test-key", "ChaCha20-Poly1305", 2, true, nil, 50*time.Millisecond, nil)
	
	events := logger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	
	event := events[0]
	if event.EventType != EventTypeDecrypt {
		t.Fatalf("expected event type %s, got %s", EventTypeDecrypt, event.EventType)
	}
	
	if event.Algorithm != "ChaCha20-Poly1305" {
		t.Fatalf("expected algorithm ChaCha20-Poly1305, got %s", event.Algorithm)
	}
}

func TestAuditLogger_LogKeyRotation(t *testing.T) {
	logger := NewLogger(100, nil)
	
	logger.LogKeyRotation(3, true, nil)
	
	events := logger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	
	event := events[0]
	if event.EventType != EventTypeKeyRotation {
		t.Fatalf("expected event type %s, got %s", EventTypeKeyRotation, event.EventType)
	}
	
	if event.KeyVersion != 3 {
		t.Fatalf("expected key version 3, got %d", event.KeyVersion)
	}
}

func TestAuditLogger_MaxEvents(t *testing.T) {
	logger := NewLogger(5, nil)
	
	// Add more events than max
	for i := 0; i < 10; i++ {
		logger.LogEncrypt("bucket", "key", "AES256-GCM", 1, true, nil, time.Millisecond, nil)
	}
	
	events := logger.GetEvents()
	if len(events) != 5 {
		t.Fatalf("expected 5 events (max), got %d", len(events))
	}
}

func TestAuditLogger_LogError(t *testing.T) {
	logger := NewLogger(100, nil)
	
	err := &testError{msg: "test error"}
	logger.LogEncrypt("bucket", "key", "AES256-GCM", 1, false, err, time.Millisecond, nil)
	
	events := logger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	
	event := events[0]
	if event.Success {
		t.Fatal("expected success to be false")
	}
	
	if event.Error != "test error" {
		t.Fatalf("expected error 'test error', got %s", event.Error)
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestAuditLogger_Redaction(t *testing.T) {
	logger := NewLoggerWithRedaction(10, nil, []string{"sensitive"})
	
	metadata := map[string]interface{}{
		"normal": "value",
		"sensitive": "secret",
	}
	
	logger.LogEncrypt("bucket", "key", "algo", 1, true, nil, 0, metadata)
	
	events := logger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	
	event := events[0]
	if event.Metadata["normal"] != "value" {
		t.Errorf("expected normal=value, got %v", event.Metadata["normal"])
	}
	if event.Metadata["sensitive"] != "[REDACTED]" {
		t.Errorf("expected sensitive=[REDACTED], got %v", event.Metadata["sensitive"])
	}
}
