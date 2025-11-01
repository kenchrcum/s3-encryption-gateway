package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestRecoveryMiddleware(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Suppress log output during tests

	tests := []struct {
		name           string
		handler        http.HandlerFunc
		expectPanic    bool
		expectedStatus int
	}{
		{
			name: "no panic",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			},
			expectPanic:    false,
			expectedStatus: http.StatusOK,
		},
		{
			name: "panic recovery",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic("test panic")
			},
			expectPanic:    true,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "nil panic",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic(nil)
			},
			expectPanic:    true,
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := RecoveryMiddleware(logger)
			wrapped := middleware(tt.handler)

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()

			// Should not panic even if handler panics
			func() {
				defer func() {
					if r := recover(); r != nil && !tt.expectPanic {
						t.Errorf("unexpected panic: %v", r)
					}
				}()
				wrapped.ServeHTTP(w, req)
			}()

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectPanic {
				// Check that error message was written
				body := w.Body.String()
				if body != "Internal Server Error\n" {
					t.Errorf("expected error message, got %q", body)
				}
			}
		})
	}
}

func TestRecoveryMiddleware_PreservesNormalHandling(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("created"))
	})

	middleware := RecoveryMiddleware(logger)
	wrapped := middleware(handler)

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	if w.Body.String() != "created" {
		t.Errorf("expected body 'created', got %q", w.Body.String())
	}
}