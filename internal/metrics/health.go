package metrics

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// HealthStatus represents the health status of the service.
type HealthStatus struct {
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Version   string            `json:"version"`
	Checks    map[string]string `json:"checks,omitempty"`
}

var (
	startTime = time.Now()
	version   = "dev"
)

// SetVersion sets the application version.
func SetVersion(v string) {
	version = v
}

// ReadyCheck is a single named readiness dependency.
type ReadyCheck struct {
	Name  string
	Check func(context.Context) error
}

// HealthHandler returns a handler for health check endpoints.
func HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := HealthStatus{
			Status:    "healthy",
			Timestamp: time.Now(),
			Version:   version,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(status)
	}
}

// ReadinessHandler returns a handler that runs all provided ReadyChecks and
// returns 200 if every check passes, or 503 if any check fails. The response
// body includes a per-component "checks" map so operators can see exactly which
// dependency caused the failure.
//
// Pass zero checks to get an unconditional 200 (e.g. when no optional
// dependencies are configured).
func ReadinessHandler(checks ...ReadyCheck) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		status := HealthStatus{
			Status:    "ready",
			Timestamp: time.Now(),
			Version:   version,
			Checks:    make(map[string]string, len(checks)),
		}

		failed := false
		for _, c := range checks {
			if err := c.Check(ctx); err != nil {
				status.Checks[c.Name] = "unavailable: " + err.Error()
				failed = true
			} else {
				status.Checks[c.Name] = "ok"
			}
		}

		if len(checks) == 0 {
			status.Checks = nil // omit empty map from JSON
		}

		w.Header().Set("Content-Type", "application/json")
		if failed {
			status.Status = "not_ready"
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		json.NewEncoder(w).Encode(status)
	}
}

// LivenessHandler returns a handler for liveness checks.
func LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := HealthStatus{
			Status:    "alive",
			Timestamp: time.Now(),
			Version:   version,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(status)
	}
}
