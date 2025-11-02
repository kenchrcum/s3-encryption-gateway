package crypto

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

func TestChunkedEncryptDecrypt_SmallData(t *testing.T) {
	engine, err := NewEngineWithChunking("test-password-12345", nil, "", nil, true, DefaultChunkSize)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Small data that fits in one chunk
	originalData := []byte("Hello, World!")
	
	// Encrypt
	reader := bytes.NewReader(originalData)
	encryptedReader, metadata, err := engine.Encrypt(reader, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Verify chunked format
	if metadata[MetaChunkedFormat] != "true" {
		t.Error("Expected chunked format marker")
	}

	// Read encrypted data
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	if len(encryptedData) == 0 {
		t.Fatal("Encrypted data is empty")
	}

	// Decrypt
	encryptedReader2 := bytes.NewReader(encryptedData)
	decryptedReader, _, err := engine.Decrypt(encryptedReader2, metadata)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}

	// Verify
	if !bytes.Equal(originalData, decryptedData) {
		t.Errorf("Decrypted data does not match original.\nOriginal: %v\nDecrypted: %v", originalData, decryptedData)
	}
}

func TestChunkedEncryptDecrypt_LargeData(t *testing.T) {
	engine, err := NewEngineWithChunking("test-password-12345", nil, "", nil, true, DefaultChunkSize)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Large data that spans multiple chunks (2MB)
	originalData := make([]byte, 2*1024*1024)
	for i := range originalData {
		originalData[i] = byte(i % 256)
	}

	// Encrypt
	reader := bytes.NewReader(originalData)
	encryptedReader, metadata, err := engine.Encrypt(reader, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Verify chunked format
	if metadata[MetaChunkedFormat] != "true" {
		t.Error("Expected chunked format marker")
	}

	// Check chunk count (should be multiple chunks)
	chunkCount := metadata[MetaChunkCount]
	if chunkCount == "" {
		t.Error("Expected chunk count in metadata")
	}

	// Read encrypted data in streaming fashion
	buffer := make([]byte, 1024)
	var encryptedData []byte
	for {
		n, err := encryptedReader.Read(buffer)
		if n > 0 {
			encryptedData = append(encryptedData, buffer[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read encrypted data: %v", err)
		}
	}

	if len(encryptedData) == 0 {
		t.Fatal("Encrypted data is empty")
	}

	// Decrypt in streaming fashion
	encryptedReader2 := bytes.NewReader(encryptedData)
	decryptedReader, _, err := engine.Decrypt(encryptedReader2, metadata)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	var decryptedData []byte
	buffer2 := make([]byte, 1024)
	for {
		n, err := decryptedReader.Read(buffer2)
		if n > 0 {
			decryptedData = append(decryptedData, buffer2[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read decrypted data: %v", err)
		}
	}

	// Verify
	if len(decryptedData) != len(originalData) {
		t.Errorf("Decrypted data length mismatch: got %d, expected %d", len(decryptedData), len(originalData))
	}

	if !bytes.Equal(originalData, decryptedData) {
		// Find first mismatch
		for i := 0; i < len(originalData) && i < len(decryptedData); i++ {
			if originalData[i] != decryptedData[i] {
				t.Errorf("Data mismatch at offset %d", i)
				break
			}
		}
		t.Error("Decrypted data does not match original")
	}
}

func TestChunkedEncryptDecrypt_ExactChunkSize(t *testing.T) {
	chunkSize := 64 * 1024 // 64KB
	engine, err := NewEngineWithChunking("test-password-12345", nil, "", nil, true, chunkSize)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Data that is exactly one chunk size
	originalData := make([]byte, chunkSize)
	for i := range originalData {
		originalData[i] = byte(i % 256)
	}

	reader := bytes.NewReader(originalData)
	encryptedReader, metadata, err := engine.Encrypt(reader, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	encryptedReader2 := bytes.NewReader(encryptedData)
	decryptedReader, _, err := engine.Decrypt(encryptedReader2, metadata)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}

	if !bytes.Equal(originalData, decryptedData) {
		t.Error("Decrypted data does not match original")
	}
}

func TestChunkedEncryptDecrypt_MultipleSizes(t *testing.T) {
	engine, err := NewEngineWithChunking("test-password-12345", nil, "", nil, true, DefaultChunkSize)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	testSizes := []int{
		1,                    // 1 byte
		100,                  // 100 bytes
		1024,                 // 1KB
		64 * 1024,            // 64KB (exact chunk size)
		65 * 1024,            // 65KB (slightly more than one chunk)
		128 * 1024,           // 128KB (two chunks)
		512 * 1024,           // 512KB
		1024 * 1024,          // 1MB
		5 * 1024 * 1024,      // 5MB
	}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			originalData := make([]byte, size)
			for i := range originalData {
				originalData[i] = byte((i * 7) % 256) // Use different pattern
			}

			reader := bytes.NewReader(originalData)
			encryptedReader, metadata, err := engine.Encrypt(reader, nil)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			encryptedData, err := io.ReadAll(encryptedReader)
			if err != nil {
				t.Fatalf("Failed to read encrypted data: %v", err)
			}

			if len(encryptedData) == 0 {
				t.Fatal("Encrypted data is empty")
			}

			encryptedReader2 := bytes.NewReader(encryptedData)
			decryptedReader, _, err := engine.Decrypt(encryptedReader2, metadata)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}

			decryptedData, err := io.ReadAll(decryptedReader)
			if err != nil {
				t.Fatalf("Failed to read decrypted data: %v", err)
			}

			if len(decryptedData) != len(originalData) {
				t.Errorf("Size mismatch: got %d, expected %d", len(decryptedData), len(originalData))
				return
			}

			if !bytes.Equal(originalData, decryptedData) {
				t.Error("Data mismatch")
			}
		})
	}
}

func TestChunkedEncryptDecrypt_StreamingBehavior(t *testing.T) {
	engine, err := NewEngineWithChunking("test-password-12345", nil, "", nil, true, 16*1024) // 16KB chunks for faster test
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Create a source that reads slowly to test streaming
	originalData := make([]byte, 100*1024) // 100KB
	for i := range originalData {
		originalData[i] = byte(i % 256)
	}

	// Encrypt with streaming source
	reader := bytes.NewReader(originalData)
	encryptedReader, metadata, err := engine.Encrypt(reader, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Read encrypted data in small chunks to verify streaming works
	encryptedChunks := make([][]byte, 0)
	buffer := make([]byte, 1024) // Read 1KB at a time
	for {
		n, err := encryptedReader.Read(buffer)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buffer[:n])
			encryptedChunks = append(encryptedChunks, chunk)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read encrypted data: %v", err)
		}
	}

	// Verify we got multiple chunks (streaming worked)
	if len(encryptedChunks) < 2 {
		t.Logf("Warning: Expected multiple chunks, got %d", len(encryptedChunks))
	}

	// Combine encrypted chunks
	var encryptedData []byte
	for _, chunk := range encryptedChunks {
		encryptedData = append(encryptedData, chunk...)
	}

	// Decrypt
	encryptedReader2 := bytes.NewReader(encryptedData)
	decryptedReader, _, err := engine.Decrypt(encryptedReader2, metadata)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}

	if !bytes.Equal(originalData, decryptedData) {
		t.Error("Decrypted data does not match original")
	}
}

func TestChunkedEncryptDecrypt_ManifestEncoding(t *testing.T) {
	// Test manifest encoding/decoding
	original := &ChunkManifest{
		Version:    1,
		ChunkSize:  64 * 1024,
		ChunkCount: 10,
		BaseIV:     "dGVzdC1iYXNlLWl2",
	}

	encoded, err := encodeManifest(original)
	if err != nil {
		t.Fatalf("Failed to encode manifest: %v", err)
	}

	decoded, err := decodeManifest(encoded)
	if err != nil {
		t.Fatalf("Failed to decode manifest: %v", err)
	}

	if decoded.Version != original.Version {
		t.Errorf("Version mismatch: got %d, expected %d", decoded.Version, original.Version)
	}
	if decoded.ChunkSize != original.ChunkSize {
		t.Errorf("ChunkSize mismatch: got %d, expected %d", decoded.ChunkSize, original.ChunkSize)
	}
	if decoded.ChunkCount != original.ChunkCount {
		t.Errorf("ChunkCount mismatch: got %d, expected %d", decoded.ChunkCount, original.ChunkCount)
	}
	if decoded.BaseIV != original.BaseIV {
		t.Errorf("BaseIV mismatch: got %s, expected %s", decoded.BaseIV, original.BaseIV)
	}
}

func TestChunkedEncryptDecrypt_BackwardCompatibility(t *testing.T) {
	// Test that chunked mode can be disabled (backward compatibility)
	engine, err := NewEngineWithChunking("test-password-12345", nil, "", nil, false, DefaultChunkSize)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	originalData := []byte("Test data")
	reader := bytes.NewReader(originalData)
	encryptedReader, metadata, err := engine.Encrypt(reader, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Should NOT be chunked format
	if metadata[MetaChunkedFormat] == "true" {
		t.Error("Expected non-chunked format when chunked mode is disabled")
	}

	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	encryptedReader2 := bytes.NewReader(encryptedData)
	decryptedReader, _, err := engine.Decrypt(encryptedReader2, metadata)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}

	if !bytes.Equal(originalData, decryptedData) {
		t.Error("Decrypted data does not match original")
	}
}
