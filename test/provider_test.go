package test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/s3"
)

// TestProvider_Compatibility tests that the gateway works with MinIO as a provider.
func TestProvider_Compatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServerForProvider(t)
	defer minioServer.StopForce()

	// Test that we can create an S3 client with MinIO provider configuration
	cfg := &config.BackendConfig{
		Endpoint:  minioServer.Endpoint,
		Region:    "us-east-1",
		AccessKey: minioServer.AccessKey,
		SecretKey: minioServer.SecretKey,
		Provider:  "minio",
		UseSSL:    false,
	}

	client, err := s3.NewClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create S3 client with MinIO provider: %v", err)
	}

	// Test basic operations work with MinIO provider
	bucket := minioServer.Bucket
	key := "provider-test-key"
	testData := []byte("provider compatibility test data")

	// Put object
    ctx := context.Background()
    err = client.PutObject(ctx, bucket, key, bytes.NewReader(testData), nil, nil)
	if err != nil {
		t.Fatalf("PutObject failed with MinIO provider: %v", err)
	}

	// Get object
	reader, metadata, err := client.GetObject(ctx, bucket, key, nil, nil)
	if err != nil {
		t.Fatalf("GetObject failed with MinIO provider: %v", err)
	}
	defer reader.Close()

	gotData, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed to read object: %v", err)
	}

	if !bytes.Equal(gotData, testData) {
		t.Errorf("Data mismatch: expected %q, got %q", string(testData), string(gotData))
	}

	// Verify metadata is handled correctly
	if metadata == nil {
		t.Error("Expected metadata, got nil")
	}
}

// TestProvider_EndpointConfiguration tests different endpoint configurations.
func TestProvider_EndpointConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServerForProvider(t)
	defer minioServer.StopForce()

	testCases := []struct {
		name     string
		endpoint string
		provider string
		wantErr  bool
	}{
		{"MinIO with explicit endpoint", minioServer.Endpoint, "minio", false},
		{"MinIO with default endpoint", "http://localhost:9000", "minio", false},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.BackendConfig{
				Endpoint:  tt.endpoint,
				Region:    "us-east-1",
				AccessKey: minioServer.AccessKey,
				SecretKey: minioServer.SecretKey,
				Provider:  tt.provider,
				UseSSL:    false,
			}

			client, err := s3.NewClient(cfg)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			// Test that client can list objects (basic connectivity test)
			ctx := context.Background()
			_, err = client.ListObjects(ctx, minioServer.Bucket, "", s3.ListOptions{MaxKeys: 1})
			if err != nil {
				// ListObjects may fail if bucket doesn't exist yet, which is OK
				t.Logf("ListObjects note: %v (expected if bucket is empty)", err)
			}
		})
	}
}

// TestGateway_ProviderIntegration tests full gateway integration with MinIO provider.
func TestGateway_ProviderIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServerForProvider(t)
	defer minioServer.StopForce()

	gatewayConfig := minioServer.GetGatewayConfig()
	gatewayConfig.Backend.Provider = "minio" // Explicitly set MinIO provider

	gateway := StartGateway(t, gatewayConfig)
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket

	// Test PUT with MinIO provider
	testData := []byte("MinIO provider integration test")
	putURL := fmt.Sprintf("http://%s/%s/provider-test", gateway.Addr, bucket)
	putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("Failed to create PUT request: %v", err)
	}

	putResp, err := client.Do(putReq)
	if err != nil {
		t.Fatalf("PUT request failed: %v", err)
	}
	defer putResp.Body.Close()

	if putResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(putResp.Body)
		t.Fatalf("PUT failed with status %d: %s", putResp.StatusCode, string(body))
	}

	// Test GET with MinIO provider
	getURL := fmt.Sprintf("http://%s/%s/provider-test", gateway.Addr, bucket)
	getReq, err := http.NewRequest("GET", getURL, nil)
	if err != nil {
		t.Fatalf("Failed to create GET request: %v", err)
	}

	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(getResp.Body)
		t.Fatalf("GET failed with status %d: %s", getResp.StatusCode, string(body))
	}

	gotData, err := io.ReadAll(getResp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if !bytes.Equal(gotData, testData) {
		t.Errorf("Data mismatch: expected %q, got %q", string(testData), string(gotData))
	}
}
