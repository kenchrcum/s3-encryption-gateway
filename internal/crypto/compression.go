package crypto

import (
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

    // Skip known non-compressible types
    if isNonCompressibleType(contentType) {
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

// isNonCompressibleType returns true for content types that should not be compressed.
func isNonCompressibleType(contentType string) bool {
    ct := strings.ToLower(strings.TrimSpace(contentType))
    if ct == "" {
        return false
    }
    // Common non-compressible prefixes
    nonPrefixes := []string{
        "image/",
        "video/",
        "audio/",
        "application/zip",
        "application/gzip",
        "application/x-gzip",
        "application/x-7z-compressed",
        "application/x-rar-compressed",
        "application/x-tar",
        "application/pdf",
    }
    for _, p := range nonPrefixes {
        if strings.HasPrefix(ct, p) {
            return true
        }
    }
    return false
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
//
// V0.6-PERF-1 Phase E: converted to a streaming implementation using
// io.Pipe so that callers (engine.Encrypt) do not need to buffer the
// compressed output separately. The post-hoc "skip if compressed ≥
// original" size check is removed per plan §E-1: the ShouldCompress
// pre-filter (size + content-type) is the industry-standard gate and is
// sufficient. Gzip overhead on uncompressible content is ≤ 20 bytes
// (negligible). ADR 0006 addendum documents this behaviour change.
func (c *compressionEngine) Compress(reader io.Reader, contentType string, size int64) (io.Reader, map[string]string, error) {
	if !c.ShouldCompress(size, contentType) {
		// Return as-is with no compression metadata
		return reader, nil, nil
	}

	switch c.algorithm {
	case "gzip", "":
		// Default to gzip. Pipe the source through a gzip.Writer in a
		// background goroutine so the caller can read compressed bytes
		// without buffering the entire payload.
		pr, pw := io.Pipe()
		go func() {
			gw, err := gzip.NewWriterLevel(pw, c.level)
			if err != nil {
				pw.CloseWithError(fmt.Errorf("failed to create gzip writer: %w", err))
				return
			}
			_, cpErr := io.Copy(gw, reader)
			closeErr := gw.Close()
			if cpErr != nil {
				pw.CloseWithError(fmt.Errorf("failed to compress data: %w", cpErr))
				return
			}
			pw.CloseWithError(closeErr)
		}()

		metadata := map[string]string{
			MetaCompressionEnabled:      "true",
			MetaCompressionAlgorithm:    "gzip",
			MetaCompressionOriginalSize: fmt.Sprintf("%d", size),
		}
		return pr, metadata, nil
	default:
		return nil, nil, fmt.Errorf("unsupported compression algorithm: %s", c.algorithm)
	}
}

// Decompress decompresses data using the provided metadata.
//
// V0.6-PERF-1 Phase E: converted to streaming. The gzip.NewReader wraps
// the source reader directly; decompressed bytes flow to the caller on
// demand without buffering the entire payload. The caller is responsible
// for fully consuming (and effectively closing) the returned reader; the
// underlying gzip.Reader is closed when it signals io.EOF.
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

	switch algorithm {
	case "gzip":
		// Wrap the source reader directly — no full-payload buffer.
		gzipReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		// Return the gzip.Reader as an io.Reader. gzip.Reader implements
		// io.ReadCloser; the Close is a no-op on the underlying reader,
		// so callers that exhaust the stream will receive io.EOF from gzip
		// transparently. For legacy engine.Decrypt the AEAD has already
		// authenticated the ciphertext before decompression begins, so
		// streaming is safe here (commit-before-release rule satisfied).
		return gzipReader, nil
	default:
		return nil, fmt.Errorf("unsupported decompression algorithm: %s", algorithm)
	}
}
