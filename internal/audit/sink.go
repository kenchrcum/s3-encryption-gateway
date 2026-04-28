package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// droppedAuditEventsTotal counts audit events dropped due to sink failures
// or backpressure. V1.0-SEC-8.
var droppedAuditEventsTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "dropped_audit_events_total",
		Help: "Total number of audit events dropped due to sink failures or backpressure",
	},
)

// Sink is an interface for audit event sinks that support closing.
type Sink interface {
	EventWriter
	Close() error
}

// BatchSink wraps an EventWriter and provides batching capability.
type BatchSink struct {
	wrapped       EventWriter
	buffer        []*AuditEvent
	bufferSize    int
	flushInterval time.Duration
	mu            sync.Mutex
	closeChan     chan struct{}
	wg            sync.WaitGroup
	retryCount    int
	retryBackoff  time.Duration
}

// NewBatchSink creates a new batched sink.
func NewBatchSink(wrapped EventWriter, size int, interval time.Duration, retryCount int, retryBackoff time.Duration) *BatchSink {
	if size <= 0 {
		size = 100
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}

	s := &BatchSink{
		wrapped:       wrapped,
		buffer:        make([]*AuditEvent, 0, size),
		bufferSize:    size,
		flushInterval: interval,
		closeChan:     make(chan struct{}),
		retryCount:    retryCount,
		retryBackoff:  retryBackoff,
	}

	s.wg.Add(1)
	go s.run()

	return s
}

// WriteEvent adds an event to the batch.
func (s *BatchSink) WriteEvent(event *AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.buffer = append(s.buffer, event)
	if len(s.buffer) >= s.bufferSize {
		// Buffer full, take all events and flush async
		events := s.drainBufferLocked()
		
		// Write asynchronously to avoid blocking the caller
		go s.writeWithRetry(events)
	}

	return nil
}

// Close stops the flush loop and flushes remaining events.
func (s *BatchSink) Close() error {
	close(s.closeChan)
	s.wg.Wait()
	return nil
}

func (s *BatchSink) run() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			events := s.drainBufferLocked()
			s.mu.Unlock()
			
			if len(events) > 0 {
				s.writeWithRetry(events)
			}
		case <-s.closeChan:
			s.mu.Lock()
			events := s.drainBufferLocked()
			s.mu.Unlock()
			
			if len(events) > 0 {
				s.writeWithRetry(events)
			}
			return
		}
	}
}

// drainBufferLocked returns the current buffer contents and clears it.
// Caller must hold the lock.
func (s *BatchSink) drainBufferLocked() []*AuditEvent {
	if len(s.buffer) == 0 {
		return nil
	}
	
	events := make([]*AuditEvent, len(s.buffer))
	copy(events, s.buffer)
	s.buffer = s.buffer[:0]
	return events
}

func (s *BatchSink) writeWithRetry(events []*AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	var err error
	for i := 0; i <= s.retryCount; i++ {
		if bw, ok := s.wrapped.(BatchWriter); ok {
			err = bw.WriteBatch(events)
		} else {
			// Serial write
			for _, event := range events {
				if e := s.wrapped.WriteEvent(event); e != nil {
					err = e
				}
			}
		}

		if err == nil {
			return nil
		}

		// In a real system, we might want to log this failure
		if i < s.retryCount {
			time.Sleep(s.retryBackoff * time.Duration(1<<uint(i)))
		}
	}
	
	fmt.Fprintf(os.Stderr, "Failed to flush audit events after %d retries: %v\n", s.retryCount, err)
	return err
}

// BatchWriter interface for sinks that support batch writing
type BatchWriter interface {
	WriteBatch(events []*AuditEvent) error
}

// HTTPSink sends events to an HTTP endpoint.
type HTTPSink struct {
	endpoint string
	client   *http.Client
	headers  map[string]string
	logger   *slog.Logger
}

// NewHTTPSink creates a new HTTP sink with default (hardened) transport settings.
// For configurable settings, use NewHTTPSinkWithConfig.
func NewHTTPSink(endpoint string, headers map[string]string) *HTTPSink {
	return NewHTTPSinkWithConfig(endpoint, headers, config.HTTPTransportConfig{})
}

// NewHTTPSinkWithConfig creates a new HTTP sink with configurable transport settings.
// V1.0-SEC-8 — hardened HTTP transport with per-phase timeouts, connection limits,
// and concurrency caps to prevent resource exhaustion.
func NewHTTPSinkWithConfig(endpoint string, headers map[string]string, cfg config.HTTPTransportConfig) *HTTPSink {
	// Apply defaults for zero values
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	maxConnsPerHost := cfg.MaxConnsPerHost
	if maxConnsPerHost == 0 {
		maxConnsPerHost = 20
	}
	maxIdleConns := cfg.MaxIdleConns
	if maxIdleConns == 0 {
		maxIdleConns = 100
	}
	maxIdleConnsPerHost := cfg.MaxIdleConnsPerHost
	if maxIdleConnsPerHost == 0 {
		maxIdleConnsPerHost = 10
	}
	idleConnTimeout := cfg.IdleConnTimeout
	if idleConnTimeout == 0 {
		idleConnTimeout = 90 * time.Second
	}
	tlsHandshakeTimeout := cfg.TLSHandshakeTimeout
	if tlsHandshakeTimeout == 0 {
		tlsHandshakeTimeout = 10 * time.Second
	}
	responseHeaderTimeout := cfg.ResponseHeaderTimeout
	if responseHeaderTimeout == 0 {
		responseHeaderTimeout = 10 * time.Second
	}

	transport := &http.Transport{
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		MaxIdleConns:          maxIdleConns,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		IdleConnTimeout:       idleConnTimeout,
		MaxConnsPerHost:       maxConnsPerHost,
	}

	return &HTTPSink{
		endpoint: endpoint,
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		headers: headers,
		logger:  slog.Default(),
	}
}

// WriteEvent writes a single event.
func (s *HTTPSink) WriteEvent(event *AuditEvent) error {
	return s.WriteBatch([]*AuditEvent{event})
}

// WriteBatch writes a batch of events.
// V1.0-SEC-8 — failures are logged via structured logging and do not block
// the caller indefinitely. Dropped events are counted.
func (s *HTTPSink) WriteBatch(events []*AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	data, err := json.Marshal(events)
	if err != nil {
		droppedAuditEventsTotal.Add(float64(len(events)))
		if s.logger != nil {
			s.logger.Error("failed to marshal audit events",
				slog.String("error", err.Error()),
				slog.Int("event_count", len(events)),
			)
		}
		return fmt.Errorf("failed to marshal audit events: %w", err)
	}

	req, err := http.NewRequest("POST", s.endpoint, bytes.NewReader(data))
	if err != nil {
		droppedAuditEventsTotal.Add(float64(len(events)))
		if s.logger != nil {
			s.logger.Error("failed to create HTTP request for audit events",
				slog.String("error", err.Error()),
				slog.Int("event_count", len(events)),
			)
		}
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		droppedAuditEventsTotal.Add(float64(len(events)))
		if s.logger != nil {
			s.logger.Error("failed to send audit events to HTTP sink",
				slog.String("error", err.Error()),
				slog.String("endpoint", s.endpoint),
				slog.Int("event_count", len(events)),
			)
		}
		return fmt.Errorf("failed to send audit events: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		droppedAuditEventsTotal.Add(float64(len(events)))
		if s.logger != nil {
			s.logger.Error("HTTP sink returned error status",
				slog.String("status", resp.Status),
				slog.String("endpoint", s.endpoint),
				slog.Int("event_count", len(events)),
			)
		}
		return fmt.Errorf("http sink returned status: %s", resp.Status)
	}

	return nil
}

// SetLogger sets the structured logger for the HTTP sink.
// If not set, slog.Default() is used.
func (s *HTTPSink) SetLogger(logger *slog.Logger) {
	s.logger = logger
}

// FileSink writes events to a file.
type FileSink struct {
	path string
	mu   sync.Mutex
}

// NewFileSink creates a new file sink.
func NewFileSink(path string) *FileSink {
	return &FileSink{path: path}
}

// WriteEvent writes a single event.
func (s *FileSink) WriteEvent(event *AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if _, err := f.Write(data); err != nil {
		return err
	}
	if _, err := f.WriteString("\n"); err != nil {
		return err
	}

	return nil
}

// StdoutSink writes events to stdout.
type StdoutSink struct{}

// WriteEvent writes a single event.
func (s *StdoutSink) WriteEvent(event *AuditEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
