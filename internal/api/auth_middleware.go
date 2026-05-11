package api

import (
	"context"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// contextKey is a private type for context keys to avoid collisions.
type contextKey int

const (
	// credentialLabelKey stores the resolved credential label in the request context.
	credentialLabelKey contextKey = iota
)

// CredentialLabelFromContext returns the credential label attached to the
// request context by AuthMiddleware, or empty string if none is present.
func CredentialLabelFromContext(r *http.Request) string {
	if label, ok := r.Context().Value(credentialLabelKey).(string); ok {
		return label
	}
	return ""
}

// writeS3ClientError writes an S3-formatted error response for authentication
// failures. It is a package-level helper so AuthMiddleware does not depend on
// Handler state.
func writeS3ClientError(w http.ResponseWriter, r *http.Request, err error, method string) {
	s3Err := classifyAuthError(err, r.URL.Path)
	s3Err.WriteXML(w)
}

// AuthMiddleware returns an HTTP middleware that validates every request
// against the credential store before passing it to next.
//
// Auth flow:
//  1. ExtractCredentials — extract access key from request.
//  2. store.Lookup       — check access key is known.
//  3. ValidateSignature  — verify HMAC (V4 or V2) using stored secret.
//  4. Attach resolved label to request context for audit logging.
//  5. Call next; on any failure return S3-formatted error.
func AuthMiddleware(store CredentialStore, clockSkew time.Duration, logger *logrus.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Extract credentials
			creds, err := ExtractCredentials(r)
			if err != nil {
				logger.WithField("path", r.URL.Path).Warn("Request with no credentials")
				writeS3ClientError(w, r, ErrMissingCredentials, r.Method)
				return
			}

			// 2. Look up access key in credential store
			secretKey, label, err := store.Lookup(creds.AccessKey)
			if err != nil {
				if err == ErrUnknownAccessKey {
					logger.WithField("access_key", creds.AccessKey).Warn("Unknown access key")
					writeS3ClientError(w, r, ErrUnknownAccessKey, r.Method)
					return
				}
				logger.WithError(err).WithField("access_key", creds.AccessKey).Warn("Credential store lookup failed")
				writeS3ClientError(w, r, ErrUnknownAccessKey, r.Method)
				return
			}

			// 3. Validate signature
			var sigErr error
			if IsSignatureV4Request(r) {
				sigErr = ValidateSignatureV4(r, secretKey, clockSkew)
			} else if IsSignatureV2Request(r) {
				sigErr = ValidateSignatureV2(r, secretKey)
			} else {
				// Credentials were extracted but no recognizable signature format
				logger.WithField("access_key", creds.AccessKey).Warn("No recognizable signature in request")
				writeS3ClientError(w, r, ErrMissingCredentials, r.Method)
				return
			}

			if sigErr != nil {
				if sigErr == ErrSignatureMismatch {
					logger.WithField("access_key", creds.AccessKey).Warn("Signature mismatch")
					writeS3ClientError(w, r, ErrSignatureMismatch, r.Method)
					return
				}
				// Other validation errors (expired, bad format, etc.)
				logger.WithError(sigErr).WithField("access_key", creds.AccessKey).Warn("Signature validation failed")
				writeS3ClientError(w, r, ErrSignatureMismatch, r.Method)
				return
			}

			// 4. Attach label to context for downstream audit logging
			if label != "" {
				r = r.WithContext(context.WithValue(r.Context(), credentialLabelKey, label))
			}

			// 5. Call next handler
			next.ServeHTTP(w, r)
		})
	}
}
