package admin

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"github.com/sirupsen/logrus"
)

// BearerAuthMiddleware returns HTTP middleware that validates an
// Authorization: Bearer <token> header using constant-time comparison.
// tokenSource is called on every request to support runtime token rotation
// (e.g. via file-watch).
func BearerAuthMiddleware(tokenSource func() []byte, logger *logrus.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeAdminError(w, http.StatusUnauthorized, "Unauthorized", "missing Authorization header")
				return
			}

			// Expect "Bearer <token>"
			const prefix = "Bearer "
			if len(authHeader) <= len(prefix) {
				writeAdminError(w, http.StatusUnauthorized, "Unauthorized", "malformed Authorization header")
				return
			}
			if authHeader[:len(prefix)] != prefix {
				writeAdminError(w, http.StatusUnauthorized, "Unauthorized", "only Bearer authentication is supported")
				return
			}

			got := []byte(authHeader[len(prefix):])
			want := tokenSource()
			if want == nil || len(want) == 0 {
				logger.Error("admin: bearer token source returned empty token")
				writeAdminError(w, http.StatusInternalServerError, "InternalError", "admin authentication misconfigured")
				return
			}

			// Constant-time comparison to prevent timing side-channels.
			if subtle.ConstantTimeCompare(got, want) != 1 {
				writeAdminError(w, http.StatusUnauthorized, "Unauthorized", "invalid bearer token")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// adminErrorResponse is the JSON error shape for admin endpoints.
type adminErrorResponse struct {
	Error struct {
		Code       string `json:"code"`
		Message    string `json:"message"`
		RotationID string `json:"rotation_id,omitempty"`
	} `json:"error"`
}

// writeAdminError writes a JSON error response for admin endpoints.
func writeAdminError(w http.ResponseWriter, status int, code, message string) {
	resp := adminErrorResponse{}
	resp.Error.Code = code
	resp.Error.Message = message
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

// WriteAdminErrorWithRotation writes a JSON error response including a rotation_id.
func WriteAdminErrorWithRotation(w http.ResponseWriter, status int, code, message, rotationID string) {
	resp := adminErrorResponse{}
	resp.Error.Code = code
	resp.Error.Message = message
	resp.Error.RotationID = rotationID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}
