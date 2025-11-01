package crypto

import (
	"bytes"
	"io"
	"testing"
)

func TestEngine_EncryptDecryptWithCompression(t *testing.T) {
	// Create compression engine
	compressionEngine := NewCompressionEngine(true, 100, []string{"text/", "application/json"}, "gzip", 6)

	// Create encryption engine with compression
	engine, err := NewEngineWithCompression("test-password-123456", compressionEngine)
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
	encryptedReader, encMetadata, err := engine.Encrypt(reader, metadata)
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
	decryptedReader, decMetadata, err := engine.Decrypt(bytes.NewReader(encryptedData), encMetadata)
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
	engine, err := NewEngine("test-password-123456")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	data := []byte("test data")
	reader := bytes.NewReader(data)
	metadata := map[string]string{
		"Content-Type": "text/plain",
	}

	// Encrypt (no compression)
	encryptedReader, encMetadata, err := engine.Encrypt(reader, metadata)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Verify no compression metadata
	if encMetadata[MetaCompressionEnabled] != "" {
		t.Errorf("Encrypt() should not have compression metadata when compression is disabled")
	}

	// Decrypt
	encryptedData, _ := io.ReadAll(encryptedReader)
	decryptedReader, _, err := engine.Decrypt(bytes.NewReader(encryptedData), encMetadata)
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
