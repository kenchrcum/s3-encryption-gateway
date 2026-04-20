package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	handler := HealthHandler()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", w.Header().Get("Content-Type"))
	}
}

func TestReadinessHandler(t *testing.T) {
	okCheck := func(name string) ReadyCheck {
		return ReadyCheck{Name: name, Check: func(_ context.Context) error { return nil }}
	}
	failCheck := func(name, msg string) ReadyCheck {
		return ReadyCheck{Name: name, Check: func(_ context.Context) error { return errors.New(msg) }}
	}

	t.Run("no checks — unconditional 200", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/readyz", nil)
		w := httptest.NewRecorder()
		ReadinessHandler()(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("want 200, got %d", w.Code)
		}
		// Checks map should be absent from JSON.
		var body HealthStatus
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Checks != nil {
			t.Errorf("expected nil checks map, got %v", body.Checks)
		}
	})

	t.Run("kms ok", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/readyz", nil)
		w := httptest.NewRecorder()
		ReadinessHandler(okCheck("kms"))(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("want 200, got %d", w.Code)
		}
	})

	t.Run("kms fail → 503", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/readyz", nil)
		w := httptest.NewRecorder()
		ReadinessHandler(failCheck("kms", "KMS unavailable"))(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("want 503, got %d", w.Code)
		}
		var body HealthStatus
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Checks["kms"] == "" {
			t.Error("expected kms entry in checks map")
		}
		if body.Status != "not_ready" {
			t.Errorf("expected not_ready, got %q", body.Status)
		}
	})

	t.Run("valkey fail → 503", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/readyz", nil)
		w := httptest.NewRecorder()
		ReadinessHandler(okCheck("kms"), failCheck("valkey", "connection refused"))(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("want 503, got %d", w.Code)
		}
		var body HealthStatus
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Checks["kms"] != "ok" {
			t.Errorf("kms check should be ok, got %q", body.Checks["kms"])
		}
		if body.Checks["valkey"] == "" {
			t.Error("expected valkey entry in checks map")
		}
	})

	t.Run("both fail — both present in checks map", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/readyz", nil)
		w := httptest.NewRecorder()
		ReadinessHandler(failCheck("kms", "kms down"), failCheck("valkey", "valkey down"))(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("want 503, got %d", w.Code)
		}
		var body HealthStatus
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Checks["kms"] == "" || body.Checks["valkey"] == "" {
			t.Errorf("expected both kms and valkey in checks; got %v", body.Checks)
		}
	})

	t.Run("both ok — 200", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/readyz", nil)
		w := httptest.NewRecorder()
		ReadinessHandler(okCheck("kms"), okCheck("valkey"))(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("want 200, got %d", w.Code)
		}
		var body HealthStatus
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Checks["kms"] != "ok" || body.Checks["valkey"] != "ok" {
			t.Errorf("both checks should be ok; got %v", body.Checks)
		}
	})
}

func TestLivenessHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/live", nil)
	w := httptest.NewRecorder()

	handler := LivenessHandler()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

