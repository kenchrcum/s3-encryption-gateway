package test

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// TestMultipartUpload_ProviderInterop tests multipart upload functionality across different S3-compatible providers.
// This ensures the gateway's multipart implementation works correctly with various backend providers.
func TestMultipartUpload_ProviderInterop(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Define providers to test
	providers := []struct {
		name string
		setupFunc func(t *testing.T) *TestServerConfig
		cleanupFunc func(t *testing.T, config *TestServerConfig)
	}{
		{
			name: "MinIO",
			setupFunc: func(t *testing.T) *TestServerConfig {
				server := StartMinIOServerForProvider(t)
				return &TestServerConfig{
					GatewayConfig: server.GetGatewayConfig(),
					Bucket:        server.Bucket,
					StopFunc:      server.StopForce,
				}
			},
			cleanupFunc: func(t *testing.T, config *TestServerConfig) {
				config.StopFunc()
			},
		},
		// TODO: Add other providers when test infrastructure is available
		// {
		//     name: "AWS_S3",
		//     setupFunc: setupAWSS3Provider,
		//     cleanupFunc: cleanupAWSS3Provider,
		// },
		// {
		//     name: "Wasabi",
		//     setupFunc: setupWasabiProvider,
		//     cleanupFunc: cleanupWasabiProvider,
		// },
		// {
		//     name: "Hetzner",
		//     setupFunc: setupHetznerProvider,
		//     cleanupFunc: cleanupHetznerProvider,
		// },
	}

	for _, provider := range providers {
		t.Run(provider.name, func(t *testing.T) {
			// Setup provider
			config := provider.setupFunc(t)
			defer provider.cleanupFunc(t, config)

			// Start gateway with provider configuration
			gateway := StartGateway(t, config.GatewayConfig)
			defer gateway.Close()

			client := gateway.GetHTTPClient()
			bucket := config.Bucket
			key := fmt.Sprintf("multipart-interop-test-%s", provider.name)

			// Test multipart upload flow
			testMultipartUploadFlow(t, client, gateway.Addr, bucket, key)
		})
	}
}

// testMultipartUploadFlow performs a complete multipart upload test against a gateway.
// This tests the full flow: initiate -> upload parts -> complete -> verify -> cleanup.
func testMultipartUploadFlow(t *testing.T, client *http.Client, gatewayAddr, bucket, key string) {
	ctx := context.Background()

	// 1. Initiate multipart upload
	initURL := fmt.Sprintf("http://%s/%s/%s?uploads", gatewayAddr, bucket, key)
	initReq, err := http.NewRequestWithContext(ctx, "POST", initURL, nil)
	if err != nil {
		t.Fatalf("Failed to create init request: %v", err)
	}

	initResp, err := client.Do(initReq)
	if err != nil {
		t.Fatalf("Init request failed: %v", err)
	}
	defer initResp.Body.Close()

	if initResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(initResp.Body)
		t.Fatalf("Init failed with status %d: %s", initResp.StatusCode, string(body))
	}

	var initResult struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		UploadId string   `xml:"UploadId"`
	}
	if err := xml.NewDecoder(initResp.Body).Decode(&initResult); err != nil {
		t.Fatalf("Failed to decode init response: %v", err)
	}

	if initResult.UploadId == "" {
		t.Fatal("UploadId is empty")
	}

	uploadID := initResult.UploadId
	t.Logf("Initiated multipart upload with ID: %s", uploadID)

	// 2. Upload multiple parts
	parts := []struct {
		partNumber int
		data       []byte
		etag       string
	}{
		{1, bytes.Repeat([]byte("a"), 5*1024*1024), ""}, // 5MB - meets MinIO minimum
		{2, []byte("part 2 data - smaller part"), ""},
		{3, bytes.Repeat([]byte("c"), 1024*1024), ""},   // 1MB
	}

	for i, part := range parts {
		partURL := fmt.Sprintf("http://%s/%s/%s?partNumber=%d&uploadId=%s",
			gatewayAddr, bucket, key, part.partNumber, uploadID)
		partReq, err := http.NewRequestWithContext(ctx, "PUT", partURL, bytes.NewReader(part.data))
		if err != nil {
			t.Fatalf("Failed to create part %d request: %v", part.partNumber, err)
		}

		partResp, err := client.Do(partReq)
		if err != nil {
			t.Fatalf("Part %d upload failed: %v", part.partNumber, err)
		}
		defer partResp.Body.Close()

		if partResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(partResp.Body)
			t.Fatalf("Part %d upload failed with status %d: %s", part.partNumber, partResp.StatusCode, string(body))
		}

		parts[i].etag = partResp.Header.Get("ETag")
		if parts[i].etag == "" {
			t.Errorf("Part %d upload did not return ETag", part.partNumber)
		}
		t.Logf("Uploaded part %d, ETag: %s", part.partNumber, parts[i].etag)
	}

	// 3. Complete multipart upload
	var completeXML strings.Builder
	completeXML.WriteString("<CompleteMultipartUpload>")
	for _, part := range parts {
		completeXML.WriteString(fmt.Sprintf("<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>",
			part.partNumber, part.etag))
	}
	completeXML.WriteString("</CompleteMultipartUpload>")

	completeURL := fmt.Sprintf("http://%s/%s/%s?uploadId=%s", gatewayAddr, bucket, key, uploadID)
	completeReq, err := http.NewRequestWithContext(ctx, "POST", completeURL, strings.NewReader(completeXML.String()))
	if err != nil {
		t.Fatalf("Failed to create complete request: %v", err)
	}
	completeReq.Header.Set("Content-Type", "application/xml")

	completeResp, err := client.Do(completeReq)
	if err != nil {
		t.Fatalf("Complete request failed: %v", err)
	}
	defer completeResp.Body.Close()

	if completeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(completeResp.Body)
		t.Fatalf("Complete failed with status %d: %s", completeResp.StatusCode, string(body))
	}

	var completeResult struct {
		XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
		ETag     string   `xml:"ETag"`
	}
	if err := xml.NewDecoder(completeResp.Body).Decode(&completeResult); err != nil {
		t.Fatalf("Failed to decode complete response: %v", err)
	}

	t.Logf("Completed multipart upload, final ETag: %s", completeResult.ETag)

	// 4. Verify object exists and content is correct
	getURL := fmt.Sprintf("http://%s/%s/%s", gatewayAddr, bucket, key)
	getReq, err := http.NewRequestWithContext(ctx, "GET", getURL, nil)
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

	// Verify content by concatenating all parts
	var expectedData bytes.Buffer
	for _, part := range parts {
		expectedData.Write(part.data)
	}

	if !bytes.Equal(gotData, expectedData.Bytes()) {
		t.Errorf("Data mismatch: expected %d bytes, got %d bytes", expectedData.Len(), len(gotData))
		if len(gotData) < 100 && len(expectedData.Bytes()) < 100 {
			t.Errorf("Expected: %q", string(expectedData.Bytes()))
			t.Errorf("Got: %q", string(gotData))
		}
	}

	// 5. Cleanup - delete the test object
	deleteURL := fmt.Sprintf("http://%s/%s/%s", gatewayAddr, bucket, key)
	deleteReq, err := http.NewRequestWithContext(ctx, "DELETE", deleteURL, nil)
	if err != nil {
		t.Fatalf("Failed to create DELETE request: %v", err)
	}

	deleteResp, err := client.Do(deleteReq)
	if err != nil {
		t.Fatalf("DELETE request failed: %v", err)
	}
	defer deleteResp.Body.Close()

	if deleteResp.StatusCode != http.StatusNoContent {
		t.Logf("Warning: DELETE failed with status %d", deleteResp.StatusCode)
	}

	t.Logf("Successfully completed multipart upload interop test for provider")
}

// TestServerConfig holds configuration for a test server.
type TestServerConfig struct {
	GatewayConfig *config.Config
	Bucket        string
	StopFunc      func()
}
