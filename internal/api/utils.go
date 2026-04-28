package api

import (
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"

	"github.com/kenneth/s3-encryption-gateway/internal/util"
)

// ipExtractor is the shared IP extractor instance configured with trusted proxies.
// It is set during server initialization via SetIPExtractor.
var ipExtractor atomic.Pointer[util.IPExtractor]

// SetIPExtractor sets the global IP extractor instance.
// This should be called once during server initialization.
func SetIPExtractor(extractor *util.IPExtractor) {
	ipExtractor.Store(extractor)
}

// getClientIP extracts the client IP address from the request.
// If an IP extractor is configured, it uses trusted proxy-aware extraction.
// Otherwise, falls back to the legacy behavior.
func getClientIP(r *http.Request) string {
	if ext := ipExtractor.Load(); ext != nil {
		return ext.GetClientIP(r)
	}

	// Fallback: use RemoteAddr directly (fail-safe)
	return util.ExtractIP(r.RemoteAddr)
}

// getRequestID extracts or generates a request ID from the request.
func getRequestID(r *http.Request) string {
	// Check for existing request ID header
	if rid := r.Header.Get("X-Request-ID"); rid != "" {
		return rid
	}

	// Could generate a new one, but for now return empty if not present
	return ""
}

// validateTags validates the x-amz-tagging header value.
// Format: URL-encoded key=value pairs, separated by &
// Limits: max 10 tags, key len 128, value len 256, specific charset
func validateTags(tagging string) error {
	if tagging == "" {
		return nil
	}

	tags, err := url.ParseQuery(tagging)
	if err != nil {
		return fmt.Errorf("invalid tagging format: %w", err)
	}

	// Count total tags (keys)
	if len(tags) > 10 {
		return fmt.Errorf("too many tags: max 10 allowed")
	}

	for k, vs := range tags {
		if len(k) > 128 {
			return fmt.Errorf("tag key too long: %s", k)
		}
		// Validate charset for key
		if !isValidTagChars(k) {
			return fmt.Errorf("invalid characters in tag key: %s", k)
		}

		for _, v := range vs {
			if len(v) > 256 {
				return fmt.Errorf("tag value too long: %s", v)
			}
			// Validate charset for value
			if !isValidTagChars(v) {
				return fmt.Errorf("invalid characters in tag value: %s", v)
			}
		}
	}
	return nil
}

// isValidTagChars checks if the string contains only allowed characters for S3 tags.
// Allowed: a-z, A-Z, 0-9, + - = . _ : /
func isValidTagChars(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '+' || c == '-' || c == '=' || c == '.' || c == '_' || c == ':' || c == '/') {
			return false
		}
	}
	return true
}
