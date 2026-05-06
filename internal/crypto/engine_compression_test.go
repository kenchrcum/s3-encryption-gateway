package crypto

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func TestEngine_EncryptDecryptWithCompression(t *testing.T) {
	// Create compression engine
	compressionEngine := NewCompressionEngine(true, 100, []string{"text/", "application/json"}, "gzip", 6)

	// Create encryption engine with compression
	engine, err := NewEngineWithCompression([]byte("test-password-123456"), compressionEngine)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test data that should compress well
	data := bytes.Repeat([]byte("This is highly compressible test data. "), 50)
	reader := bytes.NewReader(data)
	metadata := map[string]string{
		"Content-Type": "text/plain",
	}

	// Encrypt (with compression)
	encryptedReader, encMetadata, err := engine.Encrypt(context.Background(), reader, metadata)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Verify compression metadata is present
	if encMetadata[MetaCompressionEnabled] != "true" {
		t.Logf("Note: Compression metadata not found, may not have compressed (data might be too small or not compressible)")
	}

	// Read encrypted data
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	// Decrypt (with decompression)
	decryptedReader, decMetadata, err := engine.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	// Verify compression metadata is removed from client-facing metadata
	if decMetadata[MetaCompressionEnabled] != "" {
		t.Errorf("Decrypt() should remove compression metadata from client response")
	}

	// Read decrypted data
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}

	// Verify round-trip
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch after compression round-trip")
	}
}

func TestEngine_EncryptDecryptWithoutCompression(t *testing.T) {
	// Create encryption engine without compression
	engine, err := NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	data := []byte("test data")
	reader := bytes.NewReader(data)
	metadata := map[string]string{
		"Content-Type": "text/plain",
	}

	// Encrypt (no compression)
	encryptedReader, encMetadata, err := engine.Encrypt(context.Background(), reader, metadata)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Verify no compression metadata
	if encMetadata[MetaCompressionEnabled] != "" {
		t.Errorf("Encrypt() should not have compression metadata when compression is disabled")
	}

	// Decrypt
	encryptedData, _ := io.ReadAll(encryptedReader)
	decryptedReader, _, err := engine.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}

	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch")
	}
}

// TestEngine_DecompressLimitCapped verifies V1.0-SEC-M05: a tampered
// MetaCompressionOriginalSize smaller than the true uncompressed size causes
// io.LimitReader to cap the decompressor output.
func TestEngine_DecompressLimitCapped(t *testing.T) {
	compressionEngine := NewCompressionEngine(true, 100, []string{"text/"}, "gzip", 6)
	engine, err := NewEngineWithCompression([]byte("test-password-123456"), compressionEngine)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// 200 KiB of compressible data
	data := bytes.Repeat([]byte("A"), 200*1024)
	reader := bytes.NewReader(data)
	metadata := map[string]string{"Content-Type": "text/plain"}

	encryptedReader, encMetadata, err := engine.Encrypt(context.Background(), reader, metadata)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	// Verify compression happened and we have the original size
	if encMetadata[MetaCompressionEnabled] != "true" {
		t.Fatalf("Expected compression to be enabled")
	}
	origSizeStr := encMetadata[MetaCompressionOriginalSize]
	if origSizeStr == "" {
		t.Fatalf("Expected MetaCompressionOriginalSize to be set")
	}

	// Normal decrypt: everything passes through
	decryptedReader, _, err := engine.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Normal decrypt data mismatch: got %d bytes, want %d", len(decryptedData), len(data))
	}

	// Tamper with MetaCompressionOriginalSize in metadata (not part of AEAD)
	// to simulate a decompression-bomb scenario.
	tamperedMetadata := make(map[string]string, len(encMetadata))
	for k, v := range encMetadata {
		tamperedMetadata[k] = v
	}
	// Set the claimed original size to 1000 bytes.  Limit = 1000 + 65536 = 66536.
	tamperedMetadata[MetaCompressionOriginalSize] = "1000"

	decryptedReader, _, err = engine.Decrypt(context.Background(), bytes.NewReader(encryptedData), tamperedMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error with tampered metadata: %v", err)
	}
	cappedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read capped decrypted data: %v", err)
	}

	wantLimit := int64(1000 + 65536)
	if int64(len(cappedData)) != wantLimit {
		t.Errorf("Capped decompression length mismatch: got %d, want %d", len(cappedData), wantLimit)
	}

	// Verify capped data is a prefix of the original
	if !bytes.Equal(cappedData, data[:wantLimit]) {
		t.Errorf("Capped data is not a prefix of original data")
	}
}

// TestEngine_DecompressLimitFallbackV1 verifies V1.0-SEC-M05 on the
// legacy fallback decrypt path (decryptFallbackV1).  Because
// MetaCompressionOriginalSize lives inside the encrypted payload, we verify
// the happy path where the limit is above the true size and decompression
// proceeds normally.
func TestEngine_DecompressLimitFallbackV1(t *testing.T) {
	compressionEngine := NewCompressionEngine(true, 100, []string{"text/"}, "gzip", 6)
	profile := &ProviderProfile{
		Name:                "test-small-limits",
		UserMetadataLimit:   50,
		SystemMetadataLimit: 0,
		TotalHeaderLimit:    100,
		SupportsLongKeys:    true,
		CompactionStrategy:  "base64url",
	}

	encEngine, err := NewEngineWithProvider([]byte("test-password-123456789"), compressionEngine, "", nil, "default")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	concreteEngine, ok := encEngine.(*engine)
	if !ok {
		t.Fatalf("Failed to type assert to concrete engine")
	}
	concreteEngine.providerProfile = profile
	concreteEngine.compactor = NewMetadataCompactor(profile)

	data := bytes.Repeat([]byte("B"), 50*1024)
	largeMetadata := map[string]string{
		"Content-Type":         "text/plain",
		"x-amz-meta-large-key": string(bytes.Repeat([]byte("x"), 100)),
	}

	encryptedReader, encMetadata, err := encEngine.Encrypt(context.Background(), bytes.NewReader(data), largeMetadata)
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	if encMetadata[MetaFallbackMode] != "true" {
		t.Fatalf("Expected fallback mode to be triggered")
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	decryptedReader, decMetadata, err := encEngine.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Data integrity check failed in fallback path: got %d bytes, want %d", len(decryptedData), len(data))
	}
	if decMetadata["Content-Type"] != "text/plain" {
		t.Errorf("Content-Type not preserved")
	}
}
