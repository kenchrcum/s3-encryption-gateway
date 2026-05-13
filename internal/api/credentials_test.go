package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestExtractCredentials_QueryParameters(t *testing.T) {
	tests := []struct {
		name                string
		queryParams         map[string]string
		wantAccessKey       string
		wantSecretKey       string
		wantErr             bool
		wantFromQueryParam  bool
	}{
		{
			name:                "valid query parameters",
			queryParams:         map[string]string{"AWSAccessKeyId": "AKIAIOSFODNN7EXAMPLE", "AWSSecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
			wantAccessKey:       "AKIAIOSFODNN7EXAMPLE",
			wantSecretKey:       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			wantErr:             false,
			wantFromQueryParam:  true,
		},
		{
			name:        "missing access key",
			queryParams: map[string]string{"AWSSecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
			wantErr:     true,
		},
		{
			name:        "missing secret key",
			queryParams: map[string]string{"AWSAccessKeyId": "AKIAIOSFODNN7EXAMPLE"},
			wantErr:     true,
		},
		{
			name:        "empty query parameters",
			queryParams: map[string]string{},
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				URL: &url.URL{
					RawQuery: buildQueryString(tt.queryParams),
				},
			}

			creds, err := ExtractCredentials(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractCredentials() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if creds == nil {
					t.Fatal("ExtractCredentials() returned nil credentials without error")
				}
				if creds.AccessKey != tt.wantAccessKey {
					t.Errorf("ExtractCredentials() AccessKey = %v, want %v", creds.AccessKey, tt.wantAccessKey)
				}
				if creds.SecretKey != tt.wantSecretKey {
					t.Errorf("ExtractCredentials() SecretKey = %v, want %v", creds.SecretKey, tt.wantSecretKey)
				}
				if creds.FromQueryParam != tt.wantFromQueryParam {
					t.Errorf("ExtractCredentials() FromQueryParam = %v, want %v", creds.FromQueryParam, tt.wantFromQueryParam)
				}
			}
		})
	}
}

func TestExtractCredentials_AuthorizationHeader(t *testing.T) {
	tests := []struct {
		name                string
		authHeader          string
		wantAccessKey       string
		wantSecretKey       string
		wantErr             bool
		wantFromQueryParam  bool
	}{
		{
			name:                "AWS Signature V4",
			authHeader:          "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=...",
			wantAccessKey:       "AKIAIOSFODNN7EXAMPLE",
			wantSecretKey:       "", // Only access key extracted from header
			wantErr:             false,
			wantFromQueryParam:  false,
		},
		{
			name:                "Legacy AWS signature",
			authHeader:          "AWS AKIAIOSFODNN7EXAMPLE:signature",
			wantAccessKey:       "AKIAIOSFODNN7EXAMPLE",
			wantSecretKey:       "",
			wantErr:             false,
			wantFromQueryParam:  false,
		},
		{
			name:       "invalid authorization header",
			authHeader: "Bearer token",
			wantErr:    true,
		},
		{
			name:       "empty authorization header",
			authHeader: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				URL:  &url.URL{},
				Header: make(http.Header),
			}
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			creds, err := ExtractCredentials(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractCredentials() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if creds == nil {
					t.Fatal("ExtractCredentials() returned nil credentials without error")
				}
				if creds.AccessKey != tt.wantAccessKey {
					t.Errorf("ExtractCredentials() AccessKey = %v, want %v", creds.AccessKey, tt.wantAccessKey)
				}
				if creds.SecretKey != tt.wantSecretKey {
					t.Errorf("ExtractCredentials() SecretKey = %v, want %v", creds.SecretKey, tt.wantSecretKey)
				}
				if creds.FromQueryParam != tt.wantFromQueryParam {
					t.Errorf("ExtractCredentials() FromQueryParam = %v, want %v", creds.FromQueryParam, tt.wantFromQueryParam)
				}
			}
		})
	}
}

func TestHasCredentials(t *testing.T) {
	tests := []struct {
		name    string
		req     *http.Request
		want    bool
	}{
		{
			name: "has query parameters",
			req: &http.Request{
				URL: &url.URL{
					RawQuery: "AWSAccessKeyId=AKIA&AWSSecretAccessKey=secret",
				},
			},
			want: true,
		},
		{
			name: "has authorization header",
			req: &http.Request{
				URL: &url.URL{},
				Header: http.Header{
					"Authorization": []string{"AWS4-HMAC-SHA256 Credential=AKIA/.../..."},
				},
			},
			want: true,
		},
		{
			name: "no credentials",
			req: &http.Request{
				URL: &url.URL{},
				Header: make(http.Header),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasCredentials(tt.req)
			if got != tt.want {
				t.Errorf("HasCredentials() = %v, want %v", got, tt.want)
			}
		})
	}
}

func buildQueryString(params map[string]string) string {
	var parts []string
	for k, v := range params {
		parts = append(parts, k+"="+url.QueryEscape(v))
	}
	return strings.Join(parts, "&")
}

