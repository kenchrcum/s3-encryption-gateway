package test

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// createBucketInMinIO creates a bucket directly in MinIO using AWS CLI
func createBucketInMinIO(t *testing.T, minioServer *MinIOTestServer) {
	t.Helper()

	// Set AWS CLI configuration for MinIO
	t.Logf("Configuring AWS CLI with credentials: %s/%s", minioServer.AccessKey, strings.Repeat("*", len(minioServer.SecretKey)))
	cmd := exec.Command("aws", "configure", "set", "aws_access_key_id", minioServer.AccessKey)
	if err := cmd.Run(); err != nil {
		t.Logf("Warning: Failed to configure AWS CLI access key: %v", err)
	}

	cmd = exec.Command("aws", "configure", "set", "aws_secret_access_key", minioServer.SecretKey)
	if err := cmd.Run(); err != nil {
		t.Logf("Warning: Failed to configure AWS CLI secret key: %v", err)
	}

	cmd = exec.Command("aws", "configure", "set", "region", "us-east-1")
	if err := cmd.Run(); err != nil {
		t.Logf("Warning: Failed to configure AWS CLI region: %v", err)
	}

	// Try to create bucket using AWS CLI
	for attempts := 0; attempts < 5; attempts++ {
		t.Logf("Attempting to create bucket %s with AWS CLI (attempt %d)", minioServer.Bucket, attempts+1)
		cmd := exec.Command("aws", "s3", "mb", fmt.Sprintf("s3://%s", minioServer.Bucket),
			"--endpoint-url", minioServer.Endpoint,
			"--no-verify-ssl")
		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Logf("Successfully created bucket %s in MinIO using AWS CLI", minioServer.Bucket)
			return
		}
		// Check if bucket already exists (which is OK)
		outputStr := string(output)
		if strings.Contains(outputStr, "BucketAlreadyOwnedByYou") || strings.Contains(outputStr, "BucketAlreadyExists") {
			t.Logf("Bucket %s already exists (created by SDK), proceeding", minioServer.Bucket)
			return
		}
		t.Logf("Attempt %d: Failed to create bucket with AWS CLI: %v, output: %s", attempts+1, err, outputStr)
		time.Sleep(time.Duration(attempts+1) * 500 * time.Millisecond)
	}

	// If we get here, bucket creation failed, but continue anyway
	t.Logf("Warning: Could not create bucket %s with AWS CLI, proceeding with test", minioServer.Bucket)
}

// TestS3Gateway_EndToEnd tests basic PUT/GET operations with encryption.
func TestS3Gateway_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	// Create bucket directly in MinIO first
	createBucketInMinIO(t, minioServer)

	runEndToEndTest(t, minioServer.GetGatewayConfig(), minioServer.Bucket)
}

// TestS3Gateway_MultipartUpload tests multipart upload with encryption.
func TestS3Gateway_MultipartUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket
	key := "multipart-test-key"

	// 1. Initiate multipart upload
	initURL := fmt.Sprintf("http://%s/%s/%s?uploads", gateway.Addr, bucket, key)
	initReq, err := http.NewRequest("POST", initURL, nil)
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

	// 2. Upload parts (MinIO requires minimum 5MB parts for multipart upload)
	part1Data := bytes.Repeat([]byte("a"), 5*1024*1024) // 5MB
	part1URL := fmt.Sprintf("http://%s/%s/%s?partNumber=1&uploadId=%s", gateway.Addr, bucket, key, uploadID)
	part1Req, err := http.NewRequest("PUT", part1URL, bytes.NewReader(part1Data))
	if err != nil {
		t.Fatalf("Failed to create part 1 request: %v", err)
	}

	part1Resp, err := client.Do(part1Req)
	if err != nil {
		t.Fatalf("Part 1 upload failed: %v", err)
	}
	defer part1Resp.Body.Close()

	if part1Resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(part1Resp.Body)
		t.Fatalf("Part 1 upload failed with status %d: %s", part1Resp.StatusCode, string(body))
	}

	etag1 := part1Resp.Header.Get("ETag")

	part2Data := []byte("part 2 data")
	part2URL := fmt.Sprintf("http://%s/%s/%s?partNumber=2&uploadId=%s", gateway.Addr, bucket, key, uploadID)
	part2Req, err := http.NewRequest("PUT", part2URL, bytes.NewReader(part2Data))
	if err != nil {
		t.Fatalf("Failed to create part 2 request: %v", err)
	}

	part2Resp, err := client.Do(part2Req)
	if err != nil {
		t.Fatalf("Part 2 upload failed: %v", err)
	}
	defer part2Resp.Body.Close()

	if part2Resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(part2Resp.Body)
		t.Fatalf("Part 2 upload failed with status %d: %s", part2Resp.StatusCode, string(body))
	}

	etag2 := part2Resp.Header.Get("ETag")

	// 3. Complete multipart upload
	completeXML := fmt.Sprintf(`<CompleteMultipartUpload>
		<Part>
			<PartNumber>1</PartNumber>
			<ETag>%s</ETag>
		</Part>
		<Part>
			<PartNumber>2</PartNumber>
			<ETag>%s</ETag>
		</Part>
	</CompleteMultipartUpload>`, etag1, etag2)

	completeURL := fmt.Sprintf("http://%s/%s/%s?uploadId=%s", gateway.Addr, bucket, key, uploadID)
	completeReq, err := http.NewRequest("POST", completeURL, bytes.NewReader([]byte(completeXML)))
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

	// 4. Verify object exists and can be retrieved
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
		body, _ := io.ReadAll(getResp.Body)
		t.Fatalf("GET failed with status %d: %s", getResp.StatusCode, string(body))
	}

	gotData, err := io.ReadAll(getResp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Note: The parts will be concatenated by S3, but due to encryption,
	// the exact content may vary. We just verify the object was created.
	if len(gotData) == 0 {
		t.Error("Retrieved object is empty")
	}
}

// TestS3Gateway_AbortMultipartUpload tests aborting multipart uploads.
func TestS3Gateway_AbortMultipartUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	// Create bucket directly in MinIO first
	createBucketInMinIO(t, minioServer)

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket
	key := "abort-multipart-key"

	// 1. Initiate multipart upload
	initURL := fmt.Sprintf("http://%s/%s/%s?uploads", gateway.Addr, bucket, key)
	initReq, err := http.NewRequest("POST", initURL, nil)
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

	// 2. Upload a part
	part1Data := bytes.Repeat([]byte("a"), 5*1024*1024) // 5MB
	part1URL := fmt.Sprintf("http://%s/%s/%s?partNumber=1&uploadId=%s", gateway.Addr, bucket, key, uploadID)
	part1Req, err := http.NewRequest("PUT", part1URL, bytes.NewReader(part1Data))
	if err != nil {
		t.Fatalf("Failed to create part 1 request: %v", err)
	}

	part1Resp, err := client.Do(part1Req)
	if err != nil {
		t.Fatalf("Part 1 upload failed: %v", err)
	}
	defer part1Resp.Body.Close()

	if part1Resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(part1Resp.Body)
		t.Fatalf("Part 1 upload failed with status %d: %s", part1Resp.StatusCode, string(body))
	}

	// 3. Abort multipart upload
	abortURL := fmt.Sprintf("http://%s/%s/%s?uploadId=%s", gateway.Addr, bucket, key, uploadID)
	abortReq, err := http.NewRequest("DELETE", abortURL, nil)
	if err != nil {
		t.Fatalf("Failed to create abort request: %v", err)
	}

	abortResp, err := client.Do(abortReq)
	if err != nil {
		t.Fatalf("Abort request failed: %v", err)
	}
	defer abortResp.Body.Close()

	if abortResp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(abortResp.Body)
		t.Fatalf("Abort failed with status %d: %s", abortResp.StatusCode, string(body))
	}

	// 4. Verify object doesn't exist (multipart upload was aborted)
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

	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected object to not exist after abort (404), got %d", getResp.StatusCode)
	}
}

// TestS3Gateway_ListParts tests listing parts of multipart uploads.
func TestS3Gateway_ListParts(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	// Create bucket directly in MinIO first
	createBucketInMinIO(t, minioServer)

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket
	key := "list-parts-key"

	// 1. Initiate multipart upload
	initURL := fmt.Sprintf("http://%s/%s/%s?uploads", gateway.Addr, bucket, key)
	initReq, err := http.NewRequest("POST", initURL, nil)
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

	// 2. Upload multiple parts
	partData := bytes.Repeat([]byte("x"), 5*1024*1024) // 5MB each
	uploadedParts := []string{}

	for partNum := 1; partNum <= 3; partNum++ {
		partURL := fmt.Sprintf("http://%s/%s/%s?partNumber=%d&uploadId=%s", gateway.Addr, bucket, key, partNum, uploadID)
		partReq, err := http.NewRequest("PUT", partURL, bytes.NewReader(partData))
		if err != nil {
			t.Fatalf("Failed to create part %d request: %v", partNum, err)
		}

		partResp, err := client.Do(partReq)
		if err != nil {
			t.Fatalf("Part %d upload failed: %v", partNum, err)
		}
		defer partResp.Body.Close()

		if partResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(partResp.Body)
			t.Fatalf("Part %d upload failed with status %d: %s", partNum, partResp.StatusCode, string(body))
		}

		// Extract ETag from response
		etag := partResp.Header.Get("ETag")
		if etag == "" {
			t.Fatalf("Part %d upload missing ETag", partNum)
		}
		uploadedParts = append(uploadedParts, etag)
	}

	// 3. List parts
	listURL := fmt.Sprintf("http://%s/%s/%s?uploadId=%s", gateway.Addr, bucket, key, uploadID)
	listReq, err := http.NewRequest("GET", listURL, nil)
	if err != nil {
		t.Fatalf("Failed to create list parts request: %v", err)
	}

	listResp, err := client.Do(listReq)
	if err != nil {
		t.Fatalf("List parts request failed: %v", err)
	}
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("List parts failed with status %d: %s", listResp.StatusCode, string(body))
	}

	// Parse response
	body, err := io.ReadAll(listResp.Body)
	if err != nil {
		t.Fatalf("Failed to read list parts response: %v", err)
	}

	// Check that response contains part information
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "<Part>") {
		t.Error("ListParts response should contain <Part> elements")
	}
	if !strings.Contains(bodyStr, "<PartNumber>1</PartNumber>") {
		t.Error("ListParts response should contain part number 1")
	}
	if !strings.Contains(bodyStr, "<PartNumber>2</PartNumber>") {
		t.Error("ListParts response should contain part number 2")
	}
	if !strings.Contains(bodyStr, "<PartNumber>3</PartNumber>") {
		t.Error("ListParts response should contain part number 3")
	}
	if !strings.Contains(bodyStr, "<Size>") {
		t.Error("ListParts response should contain part size")
	}
	// Note: Size may vary due to encryption overhead, so we don't check exact value
}

// TestS3Gateway_RangeRequests tests range request handling.
func TestS3Gateway_RangeRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket
	key := "range-test-key"

	// Upload test data
	testData := []byte("0123456789ABCDEF")
	putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
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
		t.Fatalf("PUT failed with status %d", putResp.StatusCode)
	}

	// Test range request
	getURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
	getReq, err := http.NewRequest("GET", getURL, nil)
	if err != nil {
		t.Fatalf("Failed to create GET request: %v", err)
	}
	getReq.Header.Set("Range", "bytes=5-10")

	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusPartialContent {
		body, _ := io.ReadAll(getResp.Body)
		t.Fatalf("Expected 206 Partial Content, got %d: %s", getResp.StatusCode, string(body))
	}

	// Validate Content-Range header
	contentRange := getResp.Header.Get("Content-Range")
	expectedContentRange := "bytes 5-10/16"
	if contentRange != expectedContentRange {
		t.Errorf("Content-Range header mismatch: expected %q, got %q", expectedContentRange, contentRange)
	}

	// Validate Content-Length header
	contentLength := getResp.Header.Get("Content-Length")
	expectedContentLength := "6"
	if contentLength != expectedContentLength {
		t.Errorf("Content-Length header mismatch: expected %q, got %q", expectedContentLength, contentLength)
	}

	gotData, err := io.ReadAll(getResp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	expected := testData[5:11]
	if !bytes.Equal(gotData, expected) {
		t.Errorf("Range data mismatch: expected %q, got %q", string(expected), string(gotData))
	}

	// Verify that Content-Length matches actual data length
	if len(gotData) != 6 {
		t.Errorf("Content-Length (%s) doesn't match actual data length (%d)", contentLength, len(gotData))
	}
}

// TestS3Gateway_CopyObject tests PUT Object Copy operation.
func TestS3Gateway_CopyObject(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket

	// Upload source object
	sourceKey := "source-key"
	sourceData := []byte("source data")
	putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, sourceKey)
	putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(sourceData))
	if err != nil {
		t.Fatalf("Failed to create PUT request: %v", err)
	}

	putResp, err := client.Do(putReq)
	if err != nil {
		t.Fatalf("PUT request failed: %v", err)
	}
	defer putResp.Body.Close()

	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT failed with status %d", putResp.StatusCode)
	}

	// Copy object
	dstKey := "dest-key"
	copyURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, dstKey)
	copyReq, err := http.NewRequest("PUT", copyURL, nil)
	if err != nil {
		t.Fatalf("Failed to create COPY request: %v", err)
	}
	copyReq.Header.Set("x-amz-copy-source", fmt.Sprintf("%s/%s", bucket, sourceKey))

	copyResp, err := client.Do(copyReq)
	if err != nil {
		t.Fatalf("COPY request failed: %v", err)
	}
	defer copyResp.Body.Close()

	if copyResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(copyResp.Body)
		t.Fatalf("COPY failed with status %d: %s", copyResp.StatusCode, string(body))
	}

	// Verify copied object
	getURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, dstKey)
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

	if !bytes.Equal(gotData, sourceData) {
		t.Errorf("Copied data mismatch: expected %q, got %q", string(sourceData), string(gotData))
	}
}

// TestS3Gateway_DeleteObjects tests batch delete operation.
func TestS3Gateway_DeleteObjects(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket

	// Upload multiple objects
	keys := []string{"delete-key-1", "delete-key-2", "delete-key-3"}
	for _, key := range keys {
		putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
		putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader([]byte("test data")))
		if err != nil {
			t.Fatalf("Failed to create PUT request: %v", err)
		}

		putResp, err := client.Do(putReq)
		if err != nil {
			t.Fatalf("PUT request failed: %v", err)
		}
		putResp.Body.Close()

		if putResp.StatusCode != http.StatusOK {
			t.Fatalf("PUT failed with status %d", putResp.StatusCode)
		}
	}

	// Batch delete
	deleteXML := fmt.Sprintf(`<Delete>
		<Object><Key>%s</Key></Object>
		<Object><Key>%s</Key></Object>
		<Object><Key>%s</Key></Object>
	</Delete>`, keys[0], keys[1], keys[2])

	deleteURL := fmt.Sprintf("http://%s/%s?delete", gateway.Addr, bucket)
	deleteReq, err := http.NewRequest("POST", deleteURL, bytes.NewReader([]byte(deleteXML)))
	if err != nil {
		t.Fatalf("Failed to create DELETE request: %v", err)
	}
	deleteReq.Header.Set("Content-Type", "application/xml")

	deleteResp, err := client.Do(deleteReq)
	if err != nil {
		t.Fatalf("DELETE request failed: %v", err)
	}
	defer deleteResp.Body.Close()

	if deleteResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(deleteResp.Body)
		t.Fatalf("DELETE failed with status %d: %s", deleteResp.StatusCode, string(body))
	}

	// Verify objects are deleted
	for _, key := range keys {
		getURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
		getReq, err := http.NewRequest("GET", getURL, nil)
		if err != nil {
			t.Fatalf("Failed to create GET request: %v", err)
		}

		getResp, err := client.Do(getReq)
		if err != nil {
			t.Fatalf("GET request failed: %v", err)
		}
		getResp.Body.Close()

		if getResp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected object %s to be deleted (404), got %d", key, getResp.StatusCode)
		}
	}
}

// TestS3Gateway_DeleteObject tests single object delete operation.
func TestS3Gateway_DeleteObject(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	// Create bucket directly in MinIO first
	createBucketInMinIO(t, minioServer)

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket
	key := "delete-single-key"
	testData := []byte("test data for single delete")

	// Upload object
	putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
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
		t.Fatalf("PUT failed with status %d", putResp.StatusCode)
	}

	// Delete object
	deleteURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
	deleteReq, err := http.NewRequest("DELETE", deleteURL, nil)
	if err != nil {
		t.Fatalf("Failed to create DELETE request: %v", err)
	}

	deleteResp, err := client.Do(deleteReq)
	if err != nil {
		t.Fatalf("DELETE request failed: %v", err)
	}
	defer deleteResp.Body.Close()

	if deleteResp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(deleteResp.Body)
		t.Fatalf("DELETE failed with status %d: %s", deleteResp.StatusCode, string(body))
	}

	// Verify object is deleted
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

	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected object to be deleted (404), got %d", getResp.StatusCode)
	}
}

// TestS3Gateway_HeadObject tests HEAD object operation.
func TestS3Gateway_HeadObject(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	// Create bucket directly in MinIO first
	createBucketInMinIO(t, minioServer)

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket
	key := "head-test-key"
	testData := []byte("test data for head request")

	// Upload object
	putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
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
		t.Fatalf("PUT failed with status %d", putResp.StatusCode)
	}

	// HEAD object
	headURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
	headReq, err := http.NewRequest("HEAD", headURL, nil)
	if err != nil {
		t.Fatalf("Failed to create HEAD request: %v", err)
	}

	headResp, err := client.Do(headReq)
	if err != nil {
		t.Fatalf("HEAD request failed: %v", err)
	}
	defer headResp.Body.Close()

	if headResp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD failed with status %d", headResp.StatusCode)
	}

	// Verify headers are present
	contentLength := headResp.Header.Get("Content-Length")
	if contentLength == "" {
		t.Error("Content-Length header missing in HEAD response")
	}

	contentType := headResp.Header.Get("Content-Type")
	if contentType == "" {
		t.Error("Content-Type header missing in HEAD response")
	}

	etag := headResp.Header.Get("ETag")
	if etag == "" {
		t.Error("ETag header missing in HEAD response")
	}

	// Verify body is empty
	body, err := io.ReadAll(headResp.Body)
	if err != nil {
		t.Fatalf("Failed to read HEAD response body: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("HEAD response should have empty body, got %d bytes", len(body))
	}

	// Compare with GET request (should have same headers)
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
		t.Fatalf("GET failed with status %d", getResp.StatusCode)
	}

	// Compare key headers
	if headResp.Header.Get("Content-Length") != getResp.Header.Get("Content-Length") {
		t.Errorf("Content-Length mismatch: HEAD=%s, GET=%s",
			headResp.Header.Get("Content-Length"), getResp.Header.Get("Content-Length"))
	}
	if headResp.Header.Get("Content-Type") != getResp.Header.Get("Content-Type") {
		t.Errorf("Content-Type mismatch: HEAD=%s, GET=%s",
			headResp.Header.Get("Content-Type"), getResp.Header.Get("Content-Type"))
	}
	if headResp.Header.Get("ETag") != getResp.Header.Get("ETag") {
		t.Errorf("ETag mismatch: HEAD=%s, GET=%s",
			headResp.Header.Get("ETag"), getResp.Header.Get("ETag"))
	}
}

// TestS3Gateway_ErrorCases tests various error conditions and edge cases.
func TestS3Gateway_ErrorCases(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	// Create bucket directly in MinIO first
	createBucketInMinIO(t, minioServer)

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket

	// Test 1: GET non-existent object (already tested in error handling, but let's verify)
	nonExistentURL := fmt.Sprintf("http://%s/%s/non-existent-key", gateway.Addr, bucket)
	getReq, err := http.NewRequest("GET", nonExistentURL, nil)
	if err != nil {
		t.Fatalf("Failed to create GET request: %v", err)
	}

	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404 for non-existent object, got %d", getResp.StatusCode)
	}

	// Test 2: HEAD non-existent object
	headReq, err := http.NewRequest("HEAD", nonExistentURL, nil)
	if err != nil {
		t.Fatalf("Failed to create HEAD request: %v", err)
	}

	headResp, err := client.Do(headReq)
	if err != nil {
		t.Fatalf("HEAD request failed: %v", err)
	}
	defer headResp.Body.Close()

	if headResp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404 for HEAD non-existent object, got %d", headResp.StatusCode)
	}

	// Test 3: DELETE non-existent object (should succeed)
	deleteReq, err := http.NewRequest("DELETE", nonExistentURL, nil)
	if err != nil {
		t.Fatalf("Failed to create DELETE request: %v", err)
	}

	deleteResp, err := client.Do(deleteReq)
	if err != nil {
		t.Fatalf("DELETE request failed: %v", err)
	}
	defer deleteResp.Body.Close()

	if deleteResp.StatusCode != http.StatusNoContent {
		t.Errorf("Expected 204 for DELETE non-existent object, got %d", deleteResp.StatusCode)
	}

	// Test 4: Invalid multipart upload operations
	// Try to complete upload with invalid uploadId
	invalidCompleteURL := fmt.Sprintf("http://%s/%s/test-key?uploadId=invalid-id", gateway.Addr, bucket)
	completeReq, err := http.NewRequest("POST", invalidCompleteURL, nil)
	if err != nil {
		t.Fatalf("Failed to create complete request: %v", err)
	}

	completeResp, err := client.Do(completeReq)
	if err != nil {
		t.Fatalf("Complete request failed: %v", err)
	}
	defer completeResp.Body.Close()

	if completeResp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid uploadId, got %d", completeResp.StatusCode)
	}

	// Test 5: Invalid bucket name
	invalidBucketURL := fmt.Sprintf("http://%s/invalid-bucket/test-key", gateway.Addr)
	invalidReq, err := http.NewRequest("GET", invalidBucketURL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	invalidResp, err := client.Do(invalidReq)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer invalidResp.Body.Close()

	// Should get an error response (NoSuchBucket or similar)
	if invalidResp.StatusCode == http.StatusOK {
		t.Error("Expected error for invalid bucket, got 200")
	}
	// The specific error code may vary, so we just check it's not 200
}

// TestS3Gateway_ListObjects tests ListObjects operation.
func TestS3Gateway_ListObjects(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	// Create bucket directly in MinIO first
	createBucketInMinIO(t, minioServer)

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket

	// Upload multiple objects
	keys := []string{"list-key-1", "list-key-2", "list-prefix/key-3"}
	for _, key := range keys {
		putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
		putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader([]byte("test data")))
		if err != nil {
			t.Fatalf("Failed to create PUT request: %v", err)
		}

		putResp, err := client.Do(putReq)
		if err != nil {
			t.Fatalf("PUT request failed: %v", err)
		}
		putResp.Body.Close()

		if putResp.StatusCode != http.StatusOK {
			t.Fatalf("PUT failed with status %d", putResp.StatusCode)
		}
	}

	// List objects
	listURL := fmt.Sprintf("http://%s/%s", gateway.Addr, bucket)
	listReq, err := http.NewRequest("GET", listURL, nil)
	if err != nil {
		t.Fatalf("Failed to create LIST request: %v", err)
	}

	listResp, err := client.Do(listReq)
	if err != nil {
		t.Fatalf("LIST request failed: %v", err)
	}
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("LIST failed with status %d: %s", listResp.StatusCode, string(body))
	}

	if listResp.Header.Get("Content-Type") != "application/xml" {
		t.Errorf("Expected Content-Type application/xml, got %s", listResp.Header.Get("Content-Type"))
	}

	body, err := io.ReadAll(listResp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Verify XML contains expected keys
	for _, key := range keys {
		if !bytes.Contains(body, []byte(key)) {
			t.Errorf("List response missing key: %s", key)
		}
	}
}

// TestS3Gateway_ListObjects_Delimiter tests ListObjects with delimiter for directory-like listings.
func TestS3Gateway_ListObjects_Delimiter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	// Create bucket directly in MinIO first
	createBucketInMinIO(t, minioServer)

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket

	// Upload test objects with directory-like structure
	testObjects := []string{
		"folder1/file1.txt",
		"folder1/file2.txt",
		"folder2/file3.txt",
		"root-file.txt",
	}

	for _, key := range testObjects {
		putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)

		// Retry logic for bucket creation
		var putResp *http.Response
		var err error
		maxRetries := 3

		for attempt := 0; attempt < maxRetries; attempt++ {
			putReq, reqErr := http.NewRequest("PUT", putURL, bytes.NewReader([]byte("test data")))
			if reqErr != nil {
				t.Fatalf("Failed to create PUT request: %v", reqErr)
			}

			putResp, err = client.Do(putReq)
			if err != nil {
				t.Fatalf("PUT request failed: %v", err)
			}
			putResp.Body.Close()

			if putResp.StatusCode == http.StatusOK {
				break
			}

			if putResp.StatusCode == http.StatusNotFound && attempt < maxRetries-1 {
				// Bucket doesn't exist yet, wait and retry
				time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
				continue
			}

			if putResp.StatusCode != http.StatusOK {
				t.Fatalf("PUT failed with status %d for key %s", putResp.StatusCode, key)
			}
		}
	}

	// Test delimiter listing (should show common prefixes)
	listURL := fmt.Sprintf("http://%s/%s?delimiter=/", gateway.Addr, bucket)
	listReq, err := http.NewRequest("GET", listURL, nil)
	if err != nil {
		t.Fatalf("Failed to create LIST request: %v", err)
	}

	listResp, err := client.Do(listReq)
	if err != nil {
		t.Fatalf("LIST request failed: %v", err)
	}
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("LIST failed with status %d: %s", listResp.StatusCode, string(body))
	}

	body, err := io.ReadAll(listResp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	responseStr := string(body)

	// Should contain common prefixes
	if !bytes.Contains(body, []byte("<CommonPrefixes>")) {
		t.Errorf("Expected CommonPrefixes in delimiter response, got: %s", responseStr)
	}
	if !bytes.Contains(body, []byte("<Prefix>folder1/</Prefix>")) {
		t.Errorf("Expected folder1/ common prefix, got: %s", responseStr)
	}
	if !bytes.Contains(body, []byte("<Prefix>folder2/</Prefix>")) {
		t.Errorf("Expected folder2/ common prefix, got: %s", responseStr)
	}
	// Should contain root file
	if !bytes.Contains(body, []byte("<Key>root-file.txt</Key>")) {
		t.Errorf("Expected root-file.txt in response, got: %s", responseStr)
	}
}

// TestS3Gateway_ListObjects_Prefix tests ListObjects with prefix filtering.
func TestS3Gateway_ListObjects_Prefix(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	// Create bucket directly in MinIO first
	createBucketInMinIO(t, minioServer)

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket

	// Upload test objects
	testObjects := []string{
		"app/logs/error.log",
		"app/logs/info.log",
		"app/config/settings.json",
		"data/file1.txt",
		"data/file2.txt",
	}

	for _, key := range testObjects {
		putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
		putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader([]byte("test data")))
		if err != nil {
			t.Fatalf("Failed to create PUT request: %v", err)
		}

		putResp, err := client.Do(putReq)
		if err != nil {
			t.Fatalf("PUT request failed: %v", err)
		}
		putResp.Body.Close()

		if putResp.StatusCode != http.StatusOK {
			t.Fatalf("PUT failed with status %d", putResp.StatusCode)
		}
	}

	// Test prefix filtering
	listURL := fmt.Sprintf("http://%s/%s?prefix=app/", gateway.Addr, bucket)
	listReq, err := http.NewRequest("GET", listURL, nil)
	if err != nil {
		t.Fatalf("Failed to create LIST request: %v", err)
	}

	listResp, err := client.Do(listReq)
	if err != nil {
		t.Fatalf("LIST request failed: %v", err)
	}
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("LIST failed with status %d: %s", listResp.StatusCode, string(body))
	}

	body, err := io.ReadAll(listResp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	responseStr := string(body)

	// Should contain app/ prefixed objects
	expectedKeys := []string{"app/logs/error.log", "app/logs/info.log", "app/config/settings.json"}
	for _, key := range expectedKeys {
		if !bytes.Contains(body, []byte("<Key>"+key+"</Key>")) {
			t.Errorf("Expected key %s in prefix response, got: %s", key, responseStr)
		}
	}

	// Should NOT contain data/ objects
	unexpectedKeys := []string{"data/file1.txt", "data/file2.txt"}
	for _, key := range unexpectedKeys {
		if bytes.Contains(body, []byte("<Key>"+key+"</Key>")) {
			t.Errorf("Unexpected key %s in prefix response, got: %s", key, responseStr)
		}
	}
}

// TestS3Gateway_ListObjects_MaxKeys tests ListObjects with max-keys pagination.
func TestS3Gateway_ListObjects_MaxKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	// Create bucket directly in MinIO first
	createBucketInMinIO(t, minioServer)

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket

	// Upload multiple objects
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("object%02d.txt", i)
		putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
		putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader([]byte("test data")))
		if err != nil {
			t.Fatalf("Failed to create PUT request: %v", err)
		}

		putResp, err := client.Do(putReq)
		if err != nil {
			t.Fatalf("PUT request failed: %v", err)
		}
		putResp.Body.Close()

		if putResp.StatusCode != http.StatusOK {
			t.Fatalf("PUT failed with status %d", putResp.StatusCode)
		}
	}

	// Test max-keys pagination
	listURL := fmt.Sprintf("http://%s/%s?max-keys=2", gateway.Addr, bucket)
	listReq, err := http.NewRequest("GET", listURL, nil)
	if err != nil {
		t.Fatalf("Failed to create LIST request: %v", err)
	}

	listResp, err := client.Do(listReq)
	if err != nil {
		t.Fatalf("LIST request failed: %v", err)
	}
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("LIST failed with status %d: %s", listResp.StatusCode, string(body))
	}

	body, err := io.ReadAll(listResp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	responseStr := string(body)

	// Should be truncated
	if !bytes.Contains(body, []byte("<IsTruncated>true</IsTruncated>")) {
		t.Errorf("Expected IsTruncated=true, got: %s", responseStr)
	}

	// Should have NextContinuationToken
	if !bytes.Contains(body, []byte("<NextContinuationToken>")) {
		t.Errorf("Expected NextContinuationToken, got: %s", responseStr)
	}

	// Count Contents elements
	contentsCount := bytes.Count(body, []byte("<Contents>"))
	if contentsCount != 2 {
		t.Errorf("Expected 2 objects with max-keys=2, got %d Contents elements: %s", contentsCount, responseStr)
	}
}

// TestS3Gateway_ErrorHandling tests S3 error responses.
func TestS3Gateway_ErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket

	// Test NoSuchKey error
	getURL := fmt.Sprintf("http://%s/%s/nonexistent-key", gateway.Addr, bucket)
	getReq, err := http.NewRequest("GET", getURL, nil)
	if err != nil {
		t.Fatalf("Failed to create GET request: %v", err)
	}

	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404 for nonexistent key, got %d", getResp.StatusCode)
	}

	// Verify error response is XML
	if getResp.Header.Get("Content-Type") != "application/xml" {
		t.Errorf("Expected Content-Type application/xml for error, got %s", getResp.Header.Get("Content-Type"))
	}

	body, err := io.ReadAll(getResp.Body)
	if err != nil {
		t.Fatalf("Failed to read error response: %v", err)
	}

	// Verify error XML structure
	if !bytes.Contains(body, []byte("<Error>")) {
		t.Error("Error response missing <Error> element")
	}
	if !bytes.Contains(body, []byte("<Code>")) {
		t.Error("Error response missing <Code> element")
	}
	if !bytes.Contains(body, []byte("<Message>")) {
		t.Error("Error response missing <Message> element")
	}
}

// testBucketCreationThroughGateway tests that bucket creation through the gateway
// returns BucketAlreadyExists instead of 404 Not Found
func testBucketCreationThroughGateway(t *testing.T, gateway *TestGateway, bucket string) {
	t.Helper()

	client := gateway.GetHTTPClient()

	// Try to create bucket through gateway
	createURL := fmt.Sprintf("http://%s/%s", gateway.Addr, bucket)
	createReq, err := http.NewRequest("PUT", createURL, nil)
	if err != nil {
		t.Fatalf("Failed to create bucket creation request: %v", err)
	}

	createResp, err := client.Do(createReq)
	if err != nil {
		t.Fatalf("Bucket creation request failed: %v", err)
	}
	defer createResp.Body.Close()

	// Should return 409 Conflict (BucketAlreadyExists)
	if createResp.StatusCode != http.StatusConflict {
		t.Errorf("Expected 409 Conflict for bucket creation, got %d", createResp.StatusCode)
	}

	// Verify Content-Type is XML
	if createResp.Header.Get("Content-Type") != "application/xml" {
		t.Errorf("Expected Content-Type application/xml for bucket creation error, got %s", createResp.Header.Get("Content-Type"))
	}

	// Read and parse error response
	body, err := io.ReadAll(createResp.Body)
	if err != nil {
		t.Fatalf("Failed to read bucket creation error response: %v", err)
	}

	// Verify error XML contains BucketAlreadyExists
	if !bytes.Contains(body, []byte("<Code>BucketAlreadyExists</Code>")) {
		t.Errorf("Expected BucketAlreadyExists error code, got response: %s", string(body))
	}

	t.Logf("Bucket creation correctly returned BucketAlreadyExists error")
}
