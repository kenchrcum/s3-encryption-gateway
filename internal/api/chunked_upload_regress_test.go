package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestReproChunkedUploadIssue(t *testing.T) {
	// Setup
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	mockClient := newMockS3Client()

	// Use a mock engine that performs NO encryption (identity) to easily verify stored content
	// or perform simple transformation.
	// However, crypto.NewEngine returns a real engine.
	// We can use the real engine but then we need to decrypt to verify.
	// Or we can trust that if the input to Encrypt contains signatures, the ciphertext will differ from what we expect.
	// Let's use real engine, and check if the decrypted content contains signatures.

	engine, err := crypto.NewEngine("test-password-123456")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Construct AWS Chunked Body
	// 5;chunk-signature=sig1\r\nhello\r\n
	// 6;chunk-signature=sig2\r\n world\r\n
	// 0;chunk-signature=sig3\r\n

	chunk1 := "5;chunk-signature=4206fd33b3a68e398d9e04971b3d1c90024e2112c3f5c45c20e8a217b8bb2386\r\nhello\r\n"
	chunk2 := "6;chunk-signature=68c33d54ac040558907e759bdd9f9592bdd156b39da34a3788d28182774338d9\r\n world\r\n"
	chunkEnd := "0;chunk-signature=final-signature\r\n"

	body := chunk1 + chunk2 + chunkEnd

	req := httptest.NewRequest("PUT", "/test-bucket/test-key", bytes.NewReader([]byte(body)))
	// Key header indicating chunked payload
	req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	// x-amz-decoded-content-length is usually sent too
	req.Header.Set("x-amz-decoded-content-length", "11") // hello world = 11 bytes

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify stored object
	// The mock client stores the encrypted data.
	storedData, ok := mockClient.objects["test-bucket/test-key"]
	assert.True(t, ok, "Object should be stored")

	storedMeta := mockClient.metadata["test-bucket/test-key"]

	// Decrypt the stored data
	decryptedReader, _, err := engine.Decrypt(bytes.NewReader(storedData), storedMeta)
	assert.NoError(t, err)

	decryptedContent, err := io.ReadAll(decryptedReader)
	assert.NoError(t, err)

	// Checks
	expectedContent := "hello world"

	// With the fix, the decrypted content should match exact expected content
	assert.Equal(t, expectedContent, string(decryptedContent), "Decrypted content should match original payload without signatures")

	if string(decryptedContent) == expectedContent {
		t.Log("SUCCESS: Decrypted content matches expected content")
	} else {
		t.Errorf("FAILURE: Content matches mismatch. Got: %q", string(decryptedContent))
	}
}
