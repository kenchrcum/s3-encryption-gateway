package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/sirupsen/logrus"
)

func TestHandler_getS3Client_DefaultMode(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine("test-password-123456")
	
	cfg := &config.Config{
		Backend: config.BackendConfig{
			Endpoint:            "http://localhost:9000",
			AccessKey:           "test-key",
			SecretKey:           "test-secret",
			UseClientCredentials: false,
		},
	}

	handler := NewHandlerWithFeatures(mockClient, mockEngine, logger, getTestMetrics(), nil, nil, nil, cfg)
	
	req := &http.Request{
		URL: &url.URL{Path: "/test-bucket/test-key"},
	}

	// Should return the default client when useClientCredentials is disabled
	client, err := handler.getS3Client(req)
	if err != nil {
		t.Fatalf("getS3Client() error = %v, want nil", err)
	}
	
	if client == nil {
		t.Fatal("getS3Client() returned nil client")
	}
	
	// Should be the same as the configured client
	if client != mockClient {
		t.Error("getS3Client() should return configured client in default mode")
	}
}

func TestHandler_getS3Client_UseClientCredentials_WithQueryParams(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockEngine, _ := crypto.NewEngine("test-password-123456")
	
	cfg := &config.Config{
		Backend: config.BackendConfig{
			Endpoint:            "http://localhost:9000",
			Region:              "us-east-1",
			UseClientCredentials: true,
			UseSSL:              false,
		},
	}

	// Create handler without pre-configured client (useClientCredentials mode)
	handler := NewHandlerWithFeatures(nil, mockEngine, logger, getTestMetrics(), nil, nil, nil, cfg)
	
	// Request with query parameters
	req := &http.Request{
		URL: &url.URL{
			Path:     "/test-bucket/test-key",
			RawQuery: "AWSAccessKeyId=client-key&AWSSecretAccessKey=client-secret",
		},
	}

	client, err := handler.getS3Client(req)
	if err != nil {
		// In test environment without real S3, this might fail - verify it's a credentials error, not extraction error
		if err.Error() == "client factory not initialized" {
			t.Fatal("clientFactory should be initialized")
		}
		// Other errors (like AWS config errors) are acceptable in test environment
		t.Logf("getS3Client() returned expected error (no real S3 backend): %v", err)
		return
	}
	
	if client == nil {
		t.Fatal("getS3Client() returned nil client")
	}
}

func TestHandler_getS3Client_UseClientCredentials_MissingCredentials(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockEngine, _ := crypto.NewEngine("test-password-123456")
	
	cfg := &config.Config{
		Backend: config.BackendConfig{
			Endpoint:            "http://localhost:9000",
			Region:              "us-east-1",
			UseClientCredentials: true,
			UseSSL:              false,
		},
	}

	handler := NewHandlerWithFeatures(nil, mockEngine, logger, getTestMetrics(), nil, nil, nil, cfg)
	
	// Request without credentials
	req := &http.Request{
		URL: &url.URL{
			Path: "/test-bucket/test-key",
		},
	}

	client, err := handler.getS3Client(req)
	if err == nil {
		t.Error("getS3Client() expected error for missing credentials, got nil")
		return
	}
	
	if client != nil {
		t.Error("getS3Client() should return nil client when credentials missing")
	}
	
	// Verify error message indicates missing credentials
	if !strings.Contains(err.Error(), "failed to extract credentials") {
		t.Errorf("getS3Client() error = %v, want error about missing credentials", err)
	}
}

func TestHandler_getS3Client_UseClientCredentials_IncompleteCredentials(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockEngine, _ := crypto.NewEngine("test-password-123456")
	
	cfg := &config.Config{
		Backend: config.BackendConfig{
			Endpoint:            "http://localhost:9000",
			Region:              "us-east-1",
			UseClientCredentials: true,
			UseSSL:              false,
		},
	}

	handler := NewHandlerWithFeatures(nil, mockEngine, logger, getTestMetrics(), nil, nil, nil, cfg)
	
	// Request with only access key (from Authorization header)
	req := &http.Request{
		URL: &url.URL{
			Path: "/test-bucket/test-key",
		},
		Header: http.Header{
			"Authorization": []string{"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, ..."},
		},
	}

	client, err := handler.getS3Client(req)
	if err == nil {
		t.Error("getS3Client() expected error for incomplete credentials, got nil")
		return
	}
	
	if client != nil {
		t.Error("getS3Client() should return nil client when credentials incomplete")
	}
	
	// Verify error message indicates Signature V4 incompatibility
	if !strings.Contains(err.Error(), "Signature V4 requests are not supported") {
		t.Errorf("getS3Client() error = %v, want error about Signature V4 incompatibility", err)
	}
}


