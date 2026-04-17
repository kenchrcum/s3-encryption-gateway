package admin

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
