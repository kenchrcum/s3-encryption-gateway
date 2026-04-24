package api

import (
	"net/http/httptest"
	"testing"
)

// TestGetClientIP_XForwardedFor verifies extraction from X-Forwarded-For header.
func TestGetClientIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.1, 192.168.1.1")

	got := getClientIP(req)
	if got != "203.0.113.1" {
		t.Errorf("getClientIP() X-Forwarded-For = %q, want %q", got, "203.0.113.1")
	}
}

// TestGetClientIP_XRealIP verifies fallback to X-Real-IP header.
func TestGetClientIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-IP", "  10.0.0.5  ")

	got := getClientIP(req)
	if got != "10.0.0.5" {
		t.Errorf("getClientIP() X-Real-IP = %q, want %q", got, "10.0.0.5")
	}
}

// TestGetClientIP_RemoteAddr verifies fallback to RemoteAddr.
func TestGetClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	// No X-Forwarded-For or X-Real-IP; RemoteAddr is set by httptest
	req.RemoteAddr = "192.168.1.100:45678"

	got := getClientIP(req)
	if got != "192.168.1.100" {
		t.Errorf("getClientIP() RemoteAddr = %q, want %q", got, "192.168.1.100")
	}
}

// TestGetClientIP_NoInfo verifies "unknown" when no IP info is available.
func TestGetClientIP_NoInfo(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ""

	got := getClientIP(req)
	if got != "unknown" {
		t.Errorf("getClientIP() no info = %q, want %q", got, "unknown")
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
