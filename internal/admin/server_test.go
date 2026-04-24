package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/sirupsen/logrus"
)

func testLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func randomToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	return hex.EncodeToString(b)
}

// --- Bearer Auth Tests ---

func TestBearerAuth_ValidToken(t *testing.T) {
	token := randomToken(t)
	source := func() []byte { return []byte(token) }

	handler := BearerAuthMiddleware(source, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/admin/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestBearerAuth_MissingHeader(t *testing.T) {
	token := randomToken(t)
	source := func() []byte { return []byte(token) }

	handler := BearerAuthMiddleware(source, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/admin/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestBearerAuth_WrongToken(t *testing.T) {
	token := randomToken(t)
	source := func() []byte { return []byte(token) }

	handler := BearerAuthMiddleware(source, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/admin/test", nil)
	req.Header.Set("Authorization", "Bearer wrong-token-value-that-is-long")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestBearerAuth_TruncatedToken(t *testing.T) {
	token := randomToken(t)
	source := func() []byte { return []byte(token) }

	handler := BearerAuthMiddleware(source, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/admin/test", nil)
	req.Header.Set("Authorization", "Bearer "+token[:len(token)/2])
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestBearerAuth_MalformedHeader(t *testing.T) {
	token := randomToken(t)
	source := func() []byte { return []byte(token) }

	handler := BearerAuthMiddleware(source, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/admin/test", nil)
	req.Header.Set("Authorization", "Basic "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// --- Rate Limiter Tests ---

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := NewRateLimiter(10, testLogger())
	for i := 0; i < 10; i++ {
		if !rl.allow("127.0.0.1") {
			t.Fatalf("rate limiter denied request %d (under limit)", i+1)
		}
	}
}

func TestRateLimiter_DeniesOverLimit(t *testing.T) {
	rl := NewRateLimiter(5, testLogger())
	// Exhaust the bucket
	for i := 0; i < 5; i++ {
		rl.allow("127.0.0.1")
	}
	// Next request should be denied
	if rl.allow("127.0.0.1") {
		t.Fatal("rate limiter allowed request over limit")
	}
}

func TestRateLimiter_PerIP(t *testing.T) {
	rl := NewRateLimiter(3, testLogger())
	// Exhaust IP A
	for i := 0; i < 3; i++ {
		rl.allow("10.0.0.1")
	}
	// IP B should still be allowed
	if !rl.allow("10.0.0.2") {
		t.Fatal("rate limiter denied request for different IP")
	}
}

func TestRateLimiter_Middleware429(t *testing.T) {
	rl := NewRateLimiter(1, testLogger())
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request should succeed
	req := httptest.NewRequest("GET", "/admin/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on first request, got %d", w.Code)
	}

	// Second request should be rate-limited
	req = httptest.NewRequest("GET", "/admin/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on second request, got %d", w.Code)
	}
}

// --- Admin Context Tests ---

func TestIsAdminRequest_OnAdminMux(t *testing.T) {
	var isAdmin bool
	handler := adminContextMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isAdmin = IsAdminRequest(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !isAdmin {
		t.Fatal("expected IsAdminRequest=true on admin mux")
	}
}

func TestIsAdminRequest_OnDataPlane(t *testing.T) {
	// Without admin middleware, the context flag should be false
	req := httptest.NewRequest("GET", "/test", nil)
	if IsAdminRequest(req) {
		t.Fatal("expected IsAdminRequest=false on data-plane")
	}
}

// --- Integration Tests: full admin server + pprof ---

// buildAdminHandler wires the same middleware chain as Server.Start without
// binding to a real TCP port. It returns an http.Handler suitable for use
// with httptest.NewServer or httptest.NewRecorder.
func buildAdminHandler(token string, rpm int, mux *http.ServeMux, logger *logrus.Logger) http.Handler {
	var handler http.Handler = mux
	if rpm > 0 {
		rl := NewRateLimiter(rpm, logger)
		handler = rl.Middleware(handler)
	}
	source := func() []byte { return []byte(token) }
	handler = BearerAuthMiddleware(source, logger)(handler)
	handler = adminContextMiddleware(handler)
	return handler
}

// TestPprofIntegration_HeapWithValidToken verifies the full admin stack:
// adminContextMiddleware → BearerAuthMiddleware → mux → profilingHandler
// A valid bearer token to /debug/pprof/heap must return 200 with a non-empty body.
func TestPprofIntegration_HeapWithValidToken(t *testing.T) {
	token := randomToken(t)
	mux := http.NewServeMux()

	m := &fakeProfilingMetrics{}
	a := &fakeProfilingAudit{}
	cfg := config.AdminProfilingConfig{
		Enabled:               true,
		MaxConcurrentProfiles: 2,
		MaxProfileSeconds:     60,
	}
	RegisterPprofRoutes(mux, cfg, m, a, silentLogger())

	srv := httptest.NewServer(buildAdminHandler(token, 60, mux, silentLogger()))
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/debug/pprof/heap", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("expected non-empty pprof body for heap profile")
	}
	// Metric must have been incremented.
	if m.callsContaining("heap", "ok") == 0 {
		t.Errorf("expected heap:ok metric, calls: %v", m.calls)
	}
}

// TestPprofIntegration_NoToken verifies that a request without a bearer token
// returns 401 before any pprof handler is invoked.
func TestPprofIntegration_NoToken(t *testing.T) {
	mux := http.NewServeMux()
	m := &fakeProfilingMetrics{}
	a := &fakeProfilingAudit{}
	cfg := config.AdminProfilingConfig{
		Enabled:               true,
		MaxConcurrentProfiles: 2,
		MaxProfileSeconds:     60,
	}
	RegisterPprofRoutes(mux, cfg, m, a, silentLogger())

	srv := httptest.NewServer(buildAdminHandler("secret-token-xyz", 60, mux, silentLogger()))
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/debug/pprof/heap", nil)
	// Intentionally no Authorization header.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", resp.StatusCode)
	}
	// No pprof metrics should have been recorded since the handler was never reached.
	if len(m.calls) != 0 {
		t.Errorf("expected no metric calls when auth fails, got %v", m.calls)
	}
}

// TestPprofIntegration_RateLimitExhausted verifies that when the admin
// rate-limiter is exhausted all further requests receive 429.
func TestPprofIntegration_RateLimitExhausted(t *testing.T) {
	token := randomToken(t)
	mux := http.NewServeMux()
	m := &fakeProfilingMetrics{}
	a := &fakeProfilingAudit{}
	cfg := config.AdminProfilingConfig{
		Enabled:               true,
		MaxConcurrentProfiles: 5,
		MaxProfileSeconds:     60,
	}
	RegisterPprofRoutes(mux, cfg, m, a, silentLogger())

	// RPM=3 so the 4th request within the window is rate-limited.
	srv := httptest.NewServer(buildAdminHandler(token, 3, mux, silentLogger()))
	defer srv.Close()

	doReq := func() int {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/debug/pprof/heap", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// First 3 requests should succeed (under the rate limit).
	for i := 0; i < 3; i++ {
		if code := doReq(); code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, code)
		}
	}
	// 4th request must be rate-limited.
	if code := doReq(); code != http.StatusTooManyRequests {
		t.Errorf("expected 429 on 4th request, got %d", code)
	}
}

// TestPprofIntegration_DisabledRoutes404 verifies that without profiling enabled
// the /debug/pprof/* paths return 404 even with a valid token.
func TestPprofIntegration_DisabledRoutes404(t *testing.T) {
	token := randomToken(t)
	mux := http.NewServeMux()
	// Profiling disabled — no routes registered.

	srv := httptest.NewServer(buildAdminHandler(token, 60, mux, silentLogger()))
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/debug/pprof/heap", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 when profiling disabled, got %d", resp.StatusCode)
	}
}

// --- Error Response Tests ---

func TestWriteAdminError_Shape(t *testing.T) {
	w := httptest.NewRecorder()
	writeAdminError(w, http.StatusUnauthorized, "Unauthorized", "test message")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected application/json content type, got %s", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Unauthorized") {
		t.Fatalf("expected error body to contain 'Unauthorized', got: %s", body)
	}
}

// --- WriteAdminErrorWithRotation Tests ---

func TestWriteAdminErrorWithRotation_Shape(t *testing.T) {
	w := httptest.NewRecorder()
	WriteAdminErrorWithRotation(w, http.StatusConflict, "RotationConflict", "rotation in progress", "rotation-id-abc")

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected application/json content type, got %s", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "RotationConflict") {
		t.Errorf("expected body to contain 'RotationConflict', got: %s", body)
	}
	if !strings.Contains(body, "rotation-id-abc") {
		t.Errorf("expected body to contain 'rotation-id-abc', got: %s", body)
	}
	if !strings.Contains(body, "rotation in progress") {
		t.Errorf("expected body to contain message, got: %s", body)
	}
}

// --- NewServer and Server lifecycle Tests ---

func TestNewServer_CreatesMux(t *testing.T) {
	cfg := config.AdminConfig{
		Address: "127.0.0.1:0",
		Auth: config.AdminAuthConfig{
			Token: randomToken(t),
		},
	}
	s := NewServer(cfg, testLogger())
	if s == nil {
		t.Fatal("NewServer() returned nil")
	}
	mux := s.Mux()
	if mux == nil {
		t.Fatal("Server.Mux() returned nil")
	}
}

func TestServer_BoundAddr_BeforeStart(t *testing.T) {
	cfg := config.AdminConfig{
		Address: "127.0.0.1:0",
		Auth: config.AdminAuthConfig{
			Token: randomToken(t),
		},
	}
	s := NewServer(cfg, testLogger())
	addr := s.BoundAddr()
	if addr != "" {
		t.Errorf("BoundAddr() before Start() = %q, want empty string", addr)
	}
}

func TestServer_StartShutdown(t *testing.T) {
	token := randomToken(t)
	cfg := config.AdminConfig{
		Address: "127.0.0.1:0", // OS assigns port
		Auth: config.AdminAuthConfig{
			Token: token,
		},
	}
	s := NewServer(cfg, testLogger())

	// Register a simple handler
	s.Mux().HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Start server in a goroutine
	errCh := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		errCh <- s.Start(ctx)
	}()

	// Wait for the server to bind (poll BoundAddr)
	var addr string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		addr = s.BoundAddr()
		if addr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if addr == "" {
		t.Fatal("Server did not bind within 3 seconds")
	}

	// Make a request to verify the server is running
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/health", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request to server failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// Shutdown the server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := s.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Shutdown() error: %v", err)
	}

	// Wait for Start() to exit
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("Start() error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Start() did not exit after Shutdown")
	}
}

func TestServer_Shutdown_BeforeStart(t *testing.T) {
	cfg := config.AdminConfig{
		Address: "127.0.0.1:0",
		Auth: config.AdminAuthConfig{
			Token: "test-token",
		},
	}
	s := NewServer(cfg, testLogger())

	// Shutdown before Start should return nil (not panic)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := s.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() before Start() returned error: %v", err)
	}
}

// --- RateLimiter cleanup tests ---

func TestRateLimiter_Cleanup_RemovesExpiredEntries(t *testing.T) {
	// Create a rate limiter with very short TTL (via a direct test of cleanup)
	rl := NewRateLimiter(100, testLogger())

	// Add some entries by calling allow()
	rl.allow("10.0.0.1")
	rl.allow("10.0.0.2")

	// Manually set bucket lastCheck to a time in the past beyond the stale threshold
	staleTime := time.Now().Add(-10 * time.Minute) // > 5 minute stale threshold
	rl.mu.Lock()
	for _, b := range rl.buckets {
		b.lastCheck = staleTime
	}
	rl.mu.Unlock()

	// Run cleanup with "now" = current time (stale threshold = 5 minutes ago)
	rl.mu.Lock()
	rl.cleanup(time.Now())
	count := len(rl.buckets)
	rl.mu.Unlock()

	if count != 0 {
		t.Errorf("cleanup() did not remove expired entries; %d remain", count)
	}
}

// --- buildTokenSource tests ---

func TestBuildTokenSource_InlineToken(t *testing.T) {
	cfg := config.AdminConfig{
		Auth: config.AdminAuthConfig{
			Token: "my-inline-token",
		},
	}
	s := NewServer(cfg, testLogger())
	source := s.buildTokenSource()
	got := source()
	if string(got) != "my-inline-token" {
		t.Errorf("buildTokenSource() inline = %q, want %q", string(got), "my-inline-token")
	}
}

func TestBuildTokenSource_TokenFile(t *testing.T) {
	// Write a token to a temp file
	tmpFile, err := os.CreateTemp(t.TempDir(), "admin-token-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	token := "file-token-xyz"
	tmpFile.WriteString(token + "\n") // trailing newline is trimmed
	tmpFile.Close()

	cfg := config.AdminConfig{
		Auth: config.AdminAuthConfig{
			TokenFile: tmpFile.Name(),
		},
	}
	s := NewServer(cfg, testLogger())
	source := s.buildTokenSource()
	got := source()
	if string(got) != token {
		t.Errorf("buildTokenSource() file = %q, want %q", string(got), token)
	}
}

func TestBuildTokenSource_TokenFile_Missing(t *testing.T) {
	cfg := config.AdminConfig{
		Auth: config.AdminAuthConfig{
			TokenFile: "/nonexistent/path/to/token.txt",
		},
	}
	s := NewServer(cfg, testLogger())
	source := s.buildTokenSource()
	// Should return nil (not panic) when file is missing
	got := source()
	if got != nil {
		t.Errorf("buildTokenSource() with missing file should return nil, got: %q", string(got))
	}
}
