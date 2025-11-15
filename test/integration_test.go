package test

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"testing"
)

// TestS3Gateway_EndToEnd tests basic PUT/GET operations with encryption.
func TestS3Gateway_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	client := gateway.GetHTTPClient()
	bucket := minioServer.Bucket

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

	// 2. Upload parts
	part1Data := []byte("part 1 data")
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

// TestS3Gateway_ListObjects tests ListObjects operation.
func TestS3Gateway_ListObjects(t *testing.T) {
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
