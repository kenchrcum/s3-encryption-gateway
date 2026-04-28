package api

import (
	"net/http/httptest"
	"testing"

	"github.com/kenneth/s3-encryption-gateway/internal/util"
)

// TestGetClientIP_FailSafe_NoTrustedProxies verifies fail-safe behavior:
// when no trusted proxies configured, X-Forwarded-For is ignored.
func TestGetClientIP_FailSafe_NoTrustedProxies(t *testing.T) {
	// Ensure no IP extractor is set
	SetIPExtractor(nil)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:45678"
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.1, 192.168.1.1")

	// Without trusted proxies, should use RemoteAddr (fail-safe)
	got := getClientIP(req)
	if got != "192.168.1.100" {
		t.Errorf("getClientIP() without trusted proxies = %q, want %q (RemoteAddr)", got, "192.168.1.100")
	}
}

// TestGetClientIP_WithTrustedProxies verifies extraction when trusted proxies are configured.
func TestGetClientIP_WithTrustedProxies(t *testing.T) {
	// Set up IP extractor with trusted proxy
	extractor, err := util.NewIPExtractor([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("failed to create extractor: %v", err)
	}
	SetIPExtractor(extractor)
	defer SetIPExtractor(nil) // Clean up

	// From trusted proxy - should use X-Forwarded-For
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:45678"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")

	got := getClientIP(req)
	if got != "203.0.113.1" {
		t.Errorf("getClientIP() with trusted proxy = %q, want %q", got, "203.0.113.1")
	}
}

// TestGetClientIP_NonTrustedProxy verifies that requests from non-trusted IPs
// ignore X-Forwarded-For headers (V1.0-SEC-6 security fix).
func TestGetClientIP_NonTrustedProxy(t *testing.T) {
	// Set up IP extractor with trusted proxy
	extractor, err := util.NewIPExtractor([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("failed to create extractor: %v", err)
	}
	SetIPExtractor(extractor)
	defer SetIPExtractor(nil) // Clean up

	// From non-trusted IP - should ignore X-Forwarded-For
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.50:45678"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	got := getClientIP(req)
	if got != "203.0.113.50" {
		t.Errorf("getClientIP() from non-trusted = %q, want %q (RemoteAddr, spoofing prevented)", got, "203.0.113.50")
	}
}

// TestGetClientIP_RemoteAddr verifies fallback to RemoteAddr.
func TestGetClientIP_RemoteAddr(t *testing.T) {
	SetIPExtractor(nil)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:45678"

	got := getClientIP(req)
	if got != "192.168.1.100" {
		t.Errorf("getClientIP() RemoteAddr = %q, want %q", got, "192.168.1.100")
	}
}

// TestGetClientIP_NoInfo verifies empty string when no IP info is available.
func TestGetClientIP_NoInfo(t *testing.T) {
	SetIPExtractor(nil)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ""

	got := getClientIP(req)
	if got != "" {
		t.Errorf("getClientIP() no info = %q, want empty string", got)
	}
}

// TestGetRequestID_WithHeader verifies extraction from X-Request-ID header.
func TestGetRequestID_WithHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-ID", "req-abc-123")

	got := getRequestID(req)
	if got != "req-abc-123" {
		t.Errorf("getRequestID() = %q, want %q", got, "req-abc-123")
	}
}

// TestGetRequestID_Empty verifies empty string when no header is set.
func TestGetRequestID_Empty(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)

	got := getRequestID(req)
	if got != "" {
		t.Errorf("getRequestID() no header = %q, want %q", got, "")
	}
}

// TestValidateTags_Table verifies the tag validation logic with a table of inputs.
func TestValidateTags_Table(t *testing.T) {
	tests := []struct {
		name    string
		tagging string
		wantErr bool
	}{
		{"empty", "", false},
		{"single valid", "key=value", false},
		{"multiple valid", "k1=v1&k2=v2&k3=v3", false},
		{"max tags", "k1=v1&k2=v2&k3=v3&k4=v4&k5=v5&k6=v6&k7=v7&k8=v8&k9=v9&k10=v10", false},
		{"too many tags", "k1=v1&k2=v2&k3=v3&k4=v4&k5=v5&k6=v6&k7=v7&k8=v8&k9=v9&k10=v10&k11=v11", true},
		{"key too long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=v", true},
		{"invalid key chars", "key!@#=value", true},
		{"valid special chars", "key.sub-part_1:type=value-ok", false},
		{"invalid value chars", "key=value!@#", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTags(tc.tagging)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateTags(%q) error = %v, wantErr %v", tc.tagging, err, tc.wantErr)
			}
		})
	}
}

// TestIsValidTagChars_Table verifies the character validation.
func TestIsValidTagChars_Table(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"hello", true},
		{"Hello123", true},
		{"key+value", true},
		{"key-value", true},
		{"key=value", true},
		{"key.sub", true},
		{"key_sub", true},
		{"key:type", true},
		{"key/path", true},
		{"key!invalid", false},
		{"key@invalid", false},
		{"key#invalid", false},
		{"key$invalid", false},
		{"key%invalid", false},
		{"", true}, // empty string is valid
	}

	for _, tc := range tests {
		got := isValidTagChars(tc.input)
		if got != tc.want {
			t.Errorf("isValidTagChars(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}
