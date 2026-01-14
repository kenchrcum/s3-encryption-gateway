package test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
)

// runEndToEndTest runs basic PUT/GET tests against the gateway.
func runEndToEndTest(t *testing.T, gatewayConfig *config.Config, bucket string) {
	gateway := StartGateway(t, gatewayConfig)
	defer gateway.Close()

	client := gateway.GetHTTPClient()

	// Test bucket creation through gateway returns BucketAlreadyExists
	testBucketCreationThroughGateway(t, gateway, bucket)

	tests := []struct {
		name string
		key  string
		data []byte
	}{
		{"small file", "test-key-1", []byte("test data")},
		{"larger file", "test-key-2", bytes.Repeat([]byte("a"), 10240)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// PUT encrypted object
			putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, tt.key)
			putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(tt.data))
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

			// GET and verify decryption
			getURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, tt.key)
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

			if !bytes.Equal(gotData, tt.data) {
				t.Errorf("Data mismatch: expected %q, got %q", string(tt.data), string(gotData))
			}
		})
	}
}

// runChunkedUploadTest verifies that the gateway correctly handles AWS chunked uploads
// (STREAMING-UNSIGNED-PAYLOAD-TRAILER) by stripping signatures before encryption.
func runChunkedUploadTest(t *testing.T, gatewayConfig *config.Config, bucket string) {
	gateway := StartGateway(t, gatewayConfig)
	defer gateway.Close()

	client := gateway.GetHTTPClient()

	// Create test bucket (ignoring error if exists)
	testBucketCreationThroughGateway(t, gateway, bucket)

	key := "chunked-test-key"

	// Construct AWS Chunked Body manually
	// Format: HEX_SIZE;chunk-signature=HEX_SIG\r\nDATA\r\n...
	chunk1 := "5;chunk-signature=sig1\r\nhello\r\n"
	chunk2 := "6;chunk-signature=sig2\r\n world\r\n"
	chunkEnd := "0;chunk-signature=final-signature\r\n"

	bodyData := []byte(chunk1 + chunk2 + chunkEnd)
	realDataSize := 11 // "hello world"
	chunkedSize := int64(len(bodyData))

	putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
	req, err := http.NewRequest("PUT", putURL, bytes.NewReader(bodyData))
	if err != nil {
		t.Fatalf("Failed to create PUT request: %v", err)
	}

	// Set crucial headers for AWS chunked upload
	req.Header.Set("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	req.Header.Set("x-amz-decoded-content-length", fmt.Sprintf("%d", realDataSize))
	req.ContentLength = chunkedSize // Explicitly match the chunked body size

	putResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("PUT request failed: %v", err)
	}
	defer putResp.Body.Close()

	if putResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(putResp.Body)
		t.Fatalf("PUT failed with status %d: %s", putResp.StatusCode, string(respBody))
	}

	// Verify data by reading it back
	getURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
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
		respBody, _ := io.ReadAll(getResp.Body)
		t.Fatalf("GET failed with status %d: %s", getResp.StatusCode, string(respBody))
	}

	gotData, err := io.ReadAll(getResp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	expectedData := []byte("hello world")
	if !bytes.Equal(gotData, expectedData) {
		t.Errorf("Data mismatch after chunked upload/download.\nExpected: %q\nGot:      %q", string(expectedData), string(gotData))
	} else {
		t.Logf("Chunked upload verification passed: Got %q", string(gotData))
	}
}
