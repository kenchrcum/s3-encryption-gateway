package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := SecurityHeadersMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Check security headers
	headers := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Content-Security-Policy",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	for _, header := range headers {
		if rr.Header().Get(header) == "" {
			t.Errorf("Expected header %s to be set", header)
		}
	}

	// HSTS should not be set for non-TLS requests
	if rr.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS header should not be set for non-TLS requests")
	}
}

func TestSecurityHeadersMiddleware_TLS(t *testing.T) {
	handler := SecurityHeadersMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.TLS = &tls.ConnectionState{} // Simulate TLS connection
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// HSTS should be set for TLS requests
	if rr.Header().Get("Strict-Transport-Security") == "" {
		t.Error("HSTS header should be set for TLS requests")
	}
}

func TestRateLimiter(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Suppress logs during testing

	limiter := NewRateLimiter(5, 1*time.Second, logger)
	defer limiter.Stop()

	// Test allowing requests within limit
	for i := 0; i < 5; i++ {
		if !limiter.Allow("test-client") {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// Test rate limiting
	if limiter.Allow("test-client") {
		t.Error("Request should be rate limited")
	}

	// Test different clients
	if !limiter.Allow("other-client") {
		t.Error("Different client should be allowed")
	}
}

func TestRateLimiter_WindowReset(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	limiter := NewRateLimiter(5, 100*time.Millisecond, logger)
	defer limiter.Stop()

	// Exhaust limit
	for i := 0; i < 5; i++ {
		limiter.Allow("test-client")
	}

	// Should be rate limited
	if limiter.Allow("test-client") {
		t.Error("Request should be rate limited")
	}

	// Wait for window to reset
	time.Sleep(150 * time.Millisecond)

	// Should be allowed after window reset
	if !limiter.Allow("test-client") {
		t.Error("Request should be allowed after window reset")
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	limiter := NewRateLimiter(2, 1*time.Second, logger)
	defer limiter.Stop()

	handler := RateLimitMiddleware(limiter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	// First two requests should succeed
	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("Request %d should succeed, got status %d", i+1, rr.Code)
		}
	}

	// Third request should be rate limited
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status %d, got %d", http.StatusTooManyRequests, rr.Code)
	}
}

func TestGetClientKey(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	key := getClientKey(req)
	if key != "127.0.0.1:12345" {
		t.Errorf("Expected key %s, got %s", "127.0.0.1:12345", key)
	}

	// Test X-Forwarded-For header
	req.Header.Set("X-Forwarded-For", "192.168.1.1")
	key = getClientKey(req)
	if key != "192.168.1.1" {
		t.Errorf("Expected key %s, got %s", "192.168.1.1", key)
	}
}

// TestRateLimiter_CleanupRuns verifies the cleanup goroutine runs and removes
// expired entries without panicking.
func TestRateLimiter_CleanupRuns(t *testing.T) {
	// Use a very short cleanup interval so the test finishes quickly.
	rl := &RateLimiter{
		requests:        make(map[string]*tokenBucket),
		limit:           100,
		window:          1 * time.Second,
		cleanupInterval: 10 * time.Millisecond,
		stopCleanup:     make(chan struct{}),
	}

	// Add a stale entry.
	rl.mu.Lock()
	rl.requests["stale-key"] = &tokenBucket{
		tokens:     1,
		lastUpdate: time.Now().Add(-1 * time.Minute), // already expired
	}
	rl.mu.Unlock()

	// Start cleanup.
	go rl.cleanup()

	// Wait for at least one cleanup tick.
	time.Sleep(30 * time.Millisecond)

	// Stop.
	rl.Stop()

	// The stale entry should have been removed.
	rl.mu.Lock()
	_, exists := rl.requests["stale-key"]
	rl.mu.Unlock()
	if exists {
		t.Error("cleanup should have removed the stale entry")
	}
}
