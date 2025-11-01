package crypto

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

// CompressionEngine provides compression and decompression functionality.
type CompressionEngine interface {
	// Compress compresses data from the reader and returns a compressed reader
	// along with compression metadata.
	Compress(reader io.Reader, contentType string, size int64) (io.Reader, map[string]string, error)

	// Decompress decompresses data from the reader using the provided metadata.
	Decompress(reader io.Reader, metadata map[string]string) (io.Reader, error)

	// ShouldCompress determines if data should be compressed based on size and content type.
	ShouldCompress(size int64, contentType string) bool
}

// compressionEngine implements the CompressionEngine interface.
type compressionEngine struct {
	enabled      bool
	minSize      int64
	contentTypes []string
	algorithm    string
	level        int
}

// NewCompressionEngine creates a new compression engine from configuration.
func NewCompressionEngine(enabled bool, minSize int64, contentTypes []string, algorithm string, level int) CompressionEngine {
	return &compressionEngine{
		enabled:      enabled,
		minSize:      minSize,
		contentTypes: contentTypes,
		algorithm:    algorithm,
		level:        level,
	}
}

// ShouldCompress determines if data should be compressed.
func (c *compressionEngine) ShouldCompress(size int64, contentType string) bool {
	if !c.enabled {
		return false
	}

	// Check minimum size
	if size < c.minSize {
		return false
	}

	// Check content type
	if len(c.contentTypes) == 0 {
		// Default compressible types if none specified
		compressibleTypes := []string{
			"text/",
			"application/json",
			"application/xml",
			"application/javascript",
			"application/x-javascript",
			"application/x-sh",
			"application/x-csh",
			"application/x-perl",
			"application/x-python",
			"application/x-ruby",
		}
		return c.isCompressibleType(contentType, compressibleTypes)
	}

	return c.isCompressibleType(contentType, c.contentTypes)
}

// isCompressibleType checks if a content type matches any of the compressible types.
func (c *compressionEngine) isCompressibleType(contentType string, compressibleTypes []string) bool {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	for _, ct := range compressibleTypes {
		ct = strings.ToLower(strings.TrimSpace(ct))
		if strings.HasPrefix(contentType, ct) {
			return true
		}
	}
	return false
}

// Compress compresses data using the configured algorithm.
func (c *compressionEngine) Compress(reader io.Reader, contentType string, size int64) (io.Reader, map[string]string, error) {
	if !c.ShouldCompress(size, contentType) {
		// Return as-is with no compression metadata
		return reader, nil, nil
	}

	// Read source data
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read data for compression: %w", err)
	}

	originalSize := int64(len(data))

	var compressedData []byte
	var algorithm string

	switch c.algorithm {
	case "gzip", "":
		// Default to gzip
		algorithm = "gzip"
		var buf bytes.Buffer
		writer, err := gzip.NewWriterLevel(&buf, c.level)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create gzip writer: %w", err)
		}

		if _, err := writer.Write(data); err != nil {
			writer.Close()
			return nil, nil, fmt.Errorf("failed to compress data: %w", err)
		}

		if err := writer.Close(); err != nil {
			return nil, nil, fmt.Errorf("failed to close gzip writer: %w", err)
		}

		compressedData = buf.Bytes()
	default:
		return nil, nil, fmt.Errorf("unsupported compression algorithm: %s", c.algorithm)
	}

	compressedSize := int64(len(compressedData))

	// Only use compression if it actually saves space
	if compressedSize >= originalSize {
		// Compression didn't help, return original
		return bytes.NewReader(data), nil, nil
	}

	// Prepare compression metadata
	metadata := map[string]string{
		MetaCompressionEnabled:     "true",
		MetaCompressionAlgorithm:    algorithm,
		MetaCompressionOriginalSize: fmt.Sprintf("%d", originalSize),
	}

	return bytes.NewReader(compressedData), metadata, nil
}

// Decompress decompresses data using the provided metadata.
func (c *compressionEngine) Decompress(reader io.Reader, metadata map[string]string) (io.Reader, error) {
	// Check if compression was used
	compressionEnabled, ok := metadata[MetaCompressionEnabled]
	if !ok || compressionEnabled != "true" {
		// Not compressed, return as-is
		return reader, nil
	}

	algorithm, ok := metadata[MetaCompressionAlgorithm]
	if !ok {
		return nil, fmt.Errorf("compression algorithm not specified in metadata")
	}

	// Read compressed data
	compressedData, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read compressed data: %w", err)
	}

	var decompressedData []byte

	switch algorithm {
	case "gzip":
		gzipReader, err := gzip.NewReader(bytes.NewReader(compressedData))
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzipReader.Close()

		decompressedData, err = io.ReadAll(gzipReader)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress data: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported decompression algorithm: %s", algorithm)
	}

	return bytes.NewReader(decompressedData), nil
}
