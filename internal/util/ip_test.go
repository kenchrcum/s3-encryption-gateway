package util

import (
	"net/http"
	"testing"
)

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "IPv4 with port",
			input:    "192.168.1.1:8080",
			expected: "192.168.1.1",
		},
		{
			name:     "IPv4 without port",
			input:    "192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "IPv6 with port",
			input:    "[::1]:8080",
			expected: "::1",
		},
		{
			name:     "IPv6 without port",
			input:    "::1",
			expected: "::1",
		},
		{
			name:     "IPv6 bracketed without port",
			input:    "[2001:db8::1]",
			expected: "2001:db8::1",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractIP(tt.input)
			if result != tt.expected {
				t.Errorf("ExtractIP(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"loopback IPv4", "127.0.0.1", true},
		{"loopback IPv4 range", "127.0.0.53", true},
		{"private 10.x.x.x", "10.0.0.1", true},
		{"private 10.x.x.x upper", "10.255.255.255", true},
		{"private 172.16.x.x", "172.16.0.1", true},
		{"private 172.31.x.x", "172.31.255.255", true},
		{"private 192.168.x.x", "192.168.1.1", true},
		{"link-local APIPA", "169.254.0.1", true},
		{"loopback IPv6", "::1", true},
		{"IPv6 link-local", "fe80::1", true},
		{"public IP", "8.8.8.8", false},
		{"public IP Cloudflare", "1.1.1.1", false},
		{"public IPv6", "2001:4860:4860::8888", false},
		{"invalid IP", "invalid", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPrivateIP(tt.ip)
			if result != tt.expected {
				t.Errorf("isPrivateIP(%q) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestNewIPExtractor(t *testing.T) {
	tests := []struct {
		name        string
		cidrs       []string
		expectError bool
	}{
		{
			name:        "valid single CIDR",
			cidrs:       []string{"10.0.0.0/8"},
			expectError: false,
		},
		{
			name:        "valid multiple CIDRs",
			cidrs:       []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			expectError: false,
		},
		{
			name:        "empty list",
			cidrs:       []string{},
			expectError: false,
		},
		{
			name:        "invalid CIDR",
			cidrs:       []string{"invalid"},
			expectError: true,
		},
		{
			name:        "mixed valid and invalid",
			cidrs:       []string{"10.0.0.0/8", "invalid"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor, err := NewIPExtractor(tt.cidrs)
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if extractor == nil {
				t.Error("expected non-nil extractor")
			}
		})
	}
}

func TestIPExtractorGetClientIP(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		xForwardedFor  string
		xRealIP        string
		expected       string
	}{
		// Non-trusted proxy (fail-safe) - ignore XFF
		{
			name:           "no trusted proxies - uses RemoteAddr",
			trustedProxies: []string{},
			remoteAddr:     "192.168.1.100:54321",
			xForwardedFor:  "203.0.113.50, 198.51.100.10",
			expected:       "192.168.1.100",
		},
		// Trusted proxy with X-Forwarded-For
		{
			name:           "trusted proxy - finds first non-trusted IP",
			trustedProxies: []string{"10.0.0.0/8", "198.51.100.0/24"},
			remoteAddr:     "10.0.0.1:54321",
			xForwardedFor:  "203.0.113.50, 198.51.100.10",
			expected:       "203.0.113.50",
		},
		{
			name:           "trusted proxy - filters other trusted proxies from XFF",
			trustedProxies: []string{"10.0.0.0/8", "192.168.1.0/24", "198.51.100.0/24"},
			remoteAddr:     "10.0.0.1:54321",
			xForwardedFor:  "203.0.113.50, 192.168.1.50, 198.51.100.10",
			expected:       "203.0.113.50",
		},
		{
			name:           "trusted proxy - all in chain are trusted uses leftmost",
			trustedProxies: []string{"10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"},
			remoteAddr:     "10.0.0.1:54321",
			xForwardedFor:  "192.168.1.50, 172.16.0.10",
			expected:       "192.168.1.50",
		},
		// Trusted proxy with X-Real-IP
		{
			name:           "trusted proxy - uses X-Real-IP",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.0.0.1:54321",
			xRealIP:        "203.0.113.75",
			expected:       "203.0.113.75",
		},
		// Non-trusted remote IP - always uses RemoteAddr
		{
			name:           "non-trusted remote - ignores XFF",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "203.0.113.99:54321",
			xForwardedFor:  "198.51.100.10",
			expected:       "203.0.113.99",
		},
		// Multiple trusted proxy CIDRs
		{
			name:           "multiple CIDRs - match 172.16",
			trustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12"},
			remoteAddr:     "172.16.5.10:54321",
			xForwardedFor:  "203.0.113.50",
			expected:       "203.0.113.50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor, err := NewIPExtractor(tt.trustedProxies)
			if err != nil {
				t.Fatalf("failed to create extractor: %v", err)
			}

			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			result := extractor.GetClientIP(req)
			if result != tt.expected {
				t.Errorf("GetClientIP() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestIPExtractorGetClientKey(t *testing.T) {
	// getClientKey should now return the same result as getClientIP
	// This test ensures the behavior is consistent
	extractor, err := NewIPExtractor([]string{"10.0.0.0/8", "198.51.100.0/24"})
	if err != nil {
		t.Fatalf("failed to create extractor: %v", err)
	}

	req := &http.Request{
		RemoteAddr: "10.0.0.1:54321",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 198.51.100.10")

	// With 198.51.100.0/24 as trusted, 198.51.100.10 is skipped
	// and 203.0.113.50 (the actual client) is returned
	ip := extractor.GetClientIP(req)
	if ip != "203.0.113.50" {
		t.Errorf("GetClientIP() = %q, expected 203.0.113.50", ip)
	}
}

func TestRateLimitBypassPrevention(t *testing.T) {
	// Test that spoofed XFF from non-trusted origin is correctly handled
	extractor, err := NewIPExtractor([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("failed to create extractor: %v", err)
	}

	// Simulate request from non-trusted IP with spoofed XFF
	req := &http.Request{
		RemoteAddr: "203.0.113.99:54321", // Non-trusted public IP
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8") // Spoofed header

	// Should return RemoteAddr, not any IP from XFF
	ip := extractor.GetClientIP(req)
	if ip != "203.0.113.99" {
		t.Errorf("GetClientIP() = %q, expected RemoteAddr 203.0.113.99 (spoofing attempt should be ignored)", ip)
	}
}
