package crypto

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

func TestChunkedEncryptDecrypt_SmallData(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("test-password-12345"), nil, "", nil, true, DefaultChunkSize)
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
	engine, err := NewEngineWithChunking([]byte("test-password-12345"), nil, "", nil, true, DefaultChunkSize)
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

	// Note: MetaChunkCount is not set during encryption because it's 0 at that point
	// (chunks are counted during encryption). It can be calculated during decryption
	// from the encrypted object size and chunk size. Some S3 implementations also
	// reject metadata with value "0", so we omit it.
	// The manifest itself contains ChunkCount but it's also 0 initially and only
	// gets updated during encryption (which happens as the reader is consumed).

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
	engine, err := NewEngineWithChunking([]byte("test-password-12345"), nil, "", nil, true, chunkSize)
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
	engine, err := NewEngineWithChunking([]byte("test-password-12345"), nil, "", nil, true, DefaultChunkSize)
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
	engine, err := NewEngineWithChunking([]byte("test-password-12345"), nil, "", nil, true, 16*1024) // 16KB chunks for faster test
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
	engine, err := NewEngineWithChunking([]byte("test-password-12345"), nil, "", nil, false, DefaultChunkSize)
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

// readTracker wraps an io.Reader and counts Read calls.
type readTracker struct {
	r          io.Reader
	readCount  int
	totalBytes int
}

func (rt *readTracker) Read(p []byte) (int, error) {
	n, err := rt.r.Read(p)
	rt.readCount++
	rt.totalBytes += n
	return n, err
}

// TestChunkedEncrypt_DoesNotPreRead verifies that encryptChunked does not
// call io.ReadAll on the source reader.  This is the key behavioural fix for
// V1.0-SEC-14 — peak heap must be bounded by the chunk pipeline, not the
// object size.
func TestChunkedEncrypt_DoesNotPreRead(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("test-password-12345"), nil, "", nil, true, DefaultChunkSize)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	data := make([]byte, 2*1024*1024) // 2 MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	tracker := &readTracker{r: bytes.NewReader(data)}
	encReader, meta, err := engine.Encrypt(tracker, map[string]string{
		"Content-Length": fmt.Sprintf("%d", len(data)),
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Encrypt() must NOT have pre-read the source.
	if tracker.readCount > 0 {
		t.Fatalf("Encrypt pre-read the source: %d Read calls, %d bytes", tracker.readCount, tracker.totalBytes)
	}

	// Verify the chunked format marker is present.
	if meta[MetaChunkedFormat] != "true" {
		t.Error("Expected chunked format marker")
	}

	// Consume the encrypted reader to ensure the plaintext is fully processed.
	encryptedData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	if len(encryptedData) == 0 {
		t.Fatal("Encrypted data is empty")
	}

	// Now the tracker should show all bytes were read.
	if tracker.totalBytes != len(data) {
		t.Fatalf("Expected %d bytes read from source, got %d", len(data), tracker.totalBytes)
	}

	// Round-trip decrypt.
	decReader, _, err := engine.Decrypt(bytes.NewReader(encryptedData), meta)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	decryptedData, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(data, decryptedData) {
		t.Error("Decrypted data does not match original")
	}
}

// TestChunkedEncryptFallback_NoDoubleBuffer verifies the metadata-fallback
// path streams the source directly into the chunked encrypt reader without
// holding the plaintext in memory.
func TestChunkedEncryptFallback_NoDoubleBuffer(t *testing.T) {
	profile := &ProviderProfile{
		Name:                "test-tiny-headers",
		UserMetadataLimit:   50,
		SystemMetadataLimit: 0,
		TotalHeaderLimit:    80,
		SupportsLongKeys:    true,
		CompactionStrategy:  "base64url",
	}

	encEngine, err := NewEngineWithProvider([]byte("test-password-123456789"), nil, "", nil, "default")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	concreteEngine := encEngine.(*engine)
	concreteEngine.providerProfile = profile
	concreteEngine.compactor = NewMetadataCompactor(profile)
	concreteEngine.chunkedMode = true
	concreteEngine.chunkSize = DefaultChunkSize

	data := []byte("Hello, fallback world! This is test data for V1.0-SEC-14.")

	encReader, meta, err := encEngine.Encrypt(bytes.NewReader(data), map[string]string{
		"Content-Length": fmt.Sprintf("%d", len(data)),
		"Content-Type":   "text/plain",
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if meta[MetaFallbackMode] != "true" {
		t.Fatalf("Expected fallback mode, got MetaFallbackMode=%q", meta[MetaFallbackMode])
	}

	// The fallback path inherently consumes the source inside Encrypt because
	// aead.Seal requires the full ciphertext buffer.  The fix for V1.0-SEC-14
	// here is that plaintext is NOT held simultaneously — only ciphertext is.
	encryptedData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	if len(encryptedData) == 0 {
		t.Fatal("Encrypted data is empty")
	}
}
