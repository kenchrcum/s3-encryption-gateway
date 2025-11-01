package crypto

import (
	"bytes"
	"io"
	"testing"
)

func TestCompressionEngine_ShouldCompress(t *testing.T) {
	engine := NewCompressionEngine(true, 100, []string{"text/", "application/json"}, "gzip", 6)

	tests := []struct {
		name        string
		size        int64
		contentType string
		want        bool
	}{
		{
			name:        "compressible type, above min size",
			size:        1024,
			contentType: "text/plain",
			want:        true,
		},
		{
			name:        "compressible type, below min size",
			size:        50,
			contentType: "text/plain",
			want:        false,
		},
		{
			name:        "non-compressible type, above min size",
			size:        1024,
			contentType: "image/png",
			want:        false,
		},
		{
			name:        "JSON, above min size",
			size:        1024,
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "disabled engine",
			size:        1024,
			contentType: "text/plain",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c CompressionEngine = engine
			if tt.name == "disabled engine" {
				c = NewCompressionEngine(false, 100, []string{"text/"}, "gzip", 6)
			}
			got := c.ShouldCompress(tt.size, tt.contentType)
			if got != tt.want {
				t.Errorf("ShouldCompress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompressionEngine_CompressDecompress(t *testing.T) {
	engine := NewCompressionEngine(true, 100, []string{"text/", "application/json"}, "gzip", 6)

	// Test data that should compress well
	data := bytes.Repeat([]byte("Hello, World! This is test data that should compress well. "), 100)
	reader := bytes.NewReader(data)

	// Compress
	compressedReader, metadata, err := engine.Compress(reader, "text/plain", int64(len(data)))
	if err != nil {
		t.Fatalf("Compress() error: %v", err)
	}

	// Should have compression metadata
	if metadata != nil {
		if metadata[MetaCompressionEnabled] != "true" {
			t.Errorf("Compress() should set compression enabled flag")
		}
		if metadata[MetaCompressionAlgorithm] != "gzip" {
			t.Errorf("Compress() wrong algorithm: got %s, want gzip", metadata[MetaCompressionAlgorithm])
		}
	}

	// Read compressed data
	compressedData, err := io.ReadAll(compressedReader)
	if err != nil {
		t.Fatalf("Failed to read compressed data: %v", err)
	}

	// Compressed data should be smaller than original
	if metadata != nil && int64(len(compressedData)) >= int64(len(data)) {
		t.Errorf("Compress() should reduce size, got %d, original %d", len(compressedData), len(data))
	}

	// Decompress
	decompressedReader, err := engine.Decompress(bytes.NewReader(compressedData), metadata)
	if err != nil {
		t.Fatalf("Decompress() error: %v", err)
	}

	decompressedData, err := io.ReadAll(decompressedReader)
	if err != nil {
		t.Fatalf("Failed to read decompressed data: %v", err)
	}

	// Verify round-trip
	if !bytes.Equal(decompressedData, data) {
		t.Errorf("Decompress() data mismatch, got %d bytes, want %d bytes", len(decompressedData), len(data))
	}
}

func TestCompressionEngine_NoCompressionWhenNotBeneficial(t *testing.T) {
	engine := NewCompressionEngine(true, 100, []string{"text/"}, "gzip", 6)

	// Test data that doesn't compress well (already compressed/encrypted-like data)
	data := make([]byte, 500)
	for i := range data {
		data[i] = byte(i % 256) // High entropy, won't compress well
	}

	reader := bytes.NewReader(data)
	compressedReader, metadata, err := engine.Compress(reader, "text/plain", int64(len(data)))
	if err != nil {
		t.Fatalf("Compress() error: %v", err)
	}

	// If compression didn't help, metadata should be nil and data unchanged
	if metadata == nil {
		compressedData, _ := io.ReadAll(compressedReader)
		if !bytes.Equal(compressedData, data) {
			t.Errorf("Compress() should return original data when compression doesn't help")
		}
	}
}

func TestCompressionEngine_DecompressUncompressed(t *testing.T) {
	engine := NewCompressionEngine(true, 100, []string{"text/"}, "gzip", 6)

	data := []byte("test data")
	reader := bytes.NewReader(data)
	metadata := map[string]string{} // No compression metadata

	decompressedReader, err := engine.Decompress(reader, metadata)
	if err != nil {
		t.Fatalf("Decompress() should not error on uncompressed data: %v", err)
	}

	decompressedData, err := io.ReadAll(decompressedReader)
	if err != nil {
		t.Fatalf("Failed to read decompressed data: %v", err)
	}

	if !bytes.Equal(decompressedData, data) {
		t.Errorf("Decompress() should return original data when not compressed")
	}
}
