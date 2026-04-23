package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
