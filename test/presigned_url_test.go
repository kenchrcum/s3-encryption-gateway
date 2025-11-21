package test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// TestS3Gateway_PresignedURL tests support for Presigned URLs.
func TestS3Gateway_PresignedURL(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	// Create bucket directly in MinIO first
	createBucketInMinIO(t, minioServer)

	// Configure gateway to use credentials (client credentials mode = false by default,
	// so it uses its configured backend credentials).
	// However, for this test, we want to verify that the gateway VALIDATES the presigned URL.
	// The current implementation only validates Presigned URLs if they match the backend credentials.
	
	gatewayConfig := minioServer.GetGatewayConfig()
	// Ensure backend credentials match what we sign with
	gatewayConfig.Backend.AccessKey = minioServer.AccessKey
	gatewayConfig.Backend.SecretKey = minioServer.SecretKey
	
	gateway := StartGateway(t, gatewayConfig)
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket
	key := "presigned-test-key"
	content := []byte("presigned data content")

	// Use aws-sdk-go-v2/service/s3 PresignClient.
	// This is the standard way to generate presigned URLs.
	// We need to create a S3 client first.
	
	// Creating S3 client pointing to Gateway
	cfg := aws.Config{
		Region: "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider(minioServer.AccessKey, minioServer.SecretKey, ""),
		EndpointResolverWithOptions: aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL: fmt.Sprintf("http://%s", gateway.Addr),
			}, nil
		}),
	}
	
	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})
	
	presigner := s3.NewPresignClient(s3Client)
	
	// 1. Presign PUT
	presignedPut, err := presigner.PresignPutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("Failed to presign PUT: %v", err)
	}
	
	// Execute PUT using Presigned URL
	// Note: presignedPut.URL contains the signed URL
	putReq, err := http.NewRequest("PUT", presignedPut.URL, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Failed to create PUT request: %v", err)
	}
	// Start with empty headers (except content-length/type which http.NewRequest might add)
	// Presigned URL shouldn't require auth headers
	
	putResp, err := client.Do(putReq)
	if err != nil {
		t.Fatalf("Presigned PUT request failed: %v", err)
	}
	defer putResp.Body.Close()
	
	if putResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(putResp.Body)
		t.Fatalf("Presigned PUT failed with status %d: %s", putResp.StatusCode, string(body))
	}
	
	// 2. Presign GET
	presignedGet, err := presigner.PresignGetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("Failed to presign GET: %v", err)
	}
	
	// Execute GET using Presigned URL
	getReq, err := http.NewRequest("GET", presignedGet.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create GET request: %v", err)
	}
	
	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("Presigned GET request failed: %v", err)
	}
	defer getResp.Body.Close()
	
	if getResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(getResp.Body)
		t.Fatalf("Presigned GET failed with status %d: %s", getResp.StatusCode, string(body))
	}
	
	gotData, err := io.ReadAll(getResp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}
	
	if !bytes.Equal(gotData, content) {
		t.Errorf("Data mismatch: expected %q, got %q", string(content), string(gotData))
	}
	
	// 3. Test Invalid Signature (Tampered URL)
	tamperedURL := presignedGet.URL + "&invalid=true"
	
	u := presignedGet.URL
	// Simple tamper: replace signature
	if idx := len(u) - 10; idx > 0 {
		tamperedURL = u[:idx] + "0000000000"
	}
	
	invalidReq, _ := http.NewRequest("GET", tamperedURL, nil)
	invalidResp, err := client.Do(invalidReq)
	if err != nil {
		t.Fatalf("Tampered request failed: %v", err)
	}
	defer invalidResp.Body.Close()
	
	if invalidResp.StatusCode != http.StatusForbidden && invalidResp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected 403 or 500 for tampered signature, got %d", invalidResp.StatusCode)
	}

	// 4. Test with Special Characters in Key
	specialKey := "folder/special key with spaces.txt"
	presignedSpecialPut, err := presigner.PresignPutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(specialKey),
	})
	if err != nil {
		t.Fatalf("Failed to presign special key PUT: %v", err)
	}
	
	specialReq, err := http.NewRequest("PUT", presignedSpecialPut.URL, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Failed to create special PUT request: %v", err)
	}
	
	specialResp, err := client.Do(specialReq)
	if err != nil {
		t.Fatalf("Special PUT request failed: %v", err)
	}
	defer specialResp.Body.Close()
	
	if specialResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(specialResp.Body)
		t.Fatalf("Special PUT failed with status %d: %s", specialResp.StatusCode, string(body))
	}
}
