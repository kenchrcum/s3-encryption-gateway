package audit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockWriter is a thread-safe mock writer.
type mockWriter struct {
	mu     sync.Mutex
	events []*AuditEvent
}

func (w *mockWriter) WriteEvent(event *AuditEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, event)
	return nil
}

func (w *mockWriter) WriteBatch(events []*AuditEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, events...)
	return nil
}

func TestBatchSink(t *testing.T) {
	mock := &mockWriter{}
	sink := NewBatchSink(mock, 5, 100*time.Millisecond, 0, 0)

	// Send 3 events (less than batch size)
	for i := 0; i < 3; i++ {
		sink.WriteEvent(&AuditEvent{Operation: fmt.Sprintf("op-%d", i)})
	}

	// Verify nothing written immediately (or shortly after)
	time.Sleep(10 * time.Millisecond)
	mock.mu.Lock()
	assert.Len(t, mock.events, 0)
	mock.mu.Unlock()

	// Wait for flush interval
	time.Sleep(150 * time.Millisecond)
	mock.mu.Lock()
	assert.Len(t, mock.events, 3)
	mock.mu.Unlock()

	// Send more events to trigger batch size flush
	for i := 0; i < 5; i++ {
		sink.WriteEvent(&AuditEvent{Operation: fmt.Sprintf("op-batch-%d", i)})
	}

	// Should flush quickly due to size limit
	time.Sleep(50 * time.Millisecond)
	mock.mu.Lock()
	assert.Len(t, mock.events, 8) // 3 + 5
	mock.mu.Unlock()

	sink.Close()
}

func TestHTTPSink(t *testing.T) {
	var capturedEvents []*AuditEvent
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		
		var events []*AuditEvent
		// Check if it's array or single object (HTTPSink sends array in batch)
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		r.Body.Close()
		
		// Try parsing as array
		if err := json.Unmarshal(body, &events); err != nil {
			// Try parsing as single object
			var event AuditEvent
			if err2 := json.Unmarshal(body, &event); err2 == nil {
				events = []*AuditEvent{&event}
			} else {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		
		capturedEvents = append(capturedEvents, events...)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	sink := NewHTTPSink(ts.URL, map[string]string{"X-Test": "true"})
	
	event := &AuditEvent{Operation: "test-http"}
	err := sink.WriteEvent(event)
	require.NoError(t, err)

	mu.Lock()
	require.Len(t, capturedEvents, 1)
	assert.Equal(t, "test-http", capturedEvents[0].Operation)
	mu.Unlock()
}

func TestFileSink(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "audit-log-*.json")
	require.NoError(t, err)
	path := tmpfile.Name()
	tmpfile.Close()
	defer os.Remove(path)

	sink := NewFileSink(path)
	event := &AuditEvent{Operation: "test-file"}
	err = sink.WriteEvent(event)
	require.NoError(t, err)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	
	// FileSink appends newline
	var loadedEvent AuditEvent
	err = json.Unmarshal(content, &loadedEvent)
	require.NoError(t, err)
	assert.Equal(t, "test-file", loadedEvent.Operation)
}

func TestNewLoggerFromConfig(t *testing.T) {
	// Test HTTP config
	cfg := config.AuditConfig{
		Enabled: true,
		Sink: config.SinkConfig{
			Type: "http",
			Endpoint: "http://localhost:1234",
			BatchSize: 10,
		},
	}

	logger, err := NewLoggerFromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, logger)
	
	// Cleanup
	if l, ok := logger.(interface{ Close() error }); ok {
		l.Close()
	}
}

