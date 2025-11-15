package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const (
	// Default chunk size for segmented encryption (64KB)
	// This balances memory usage with encryption overhead
	DefaultChunkSize = 64 * 1024

	// Minimum chunk size to ensure reasonable performance
	MinChunkSize = 16 * 1024 // 16KB

	// Maximum chunk size to prevent excessive memory usage
	MaxChunkSize = 1024 * 1024 // 1MB

	// Metadata key for chunked encryption format
	MetaChunkedFormat = "x-amz-meta-encryption-chunked"
	MetaChunkSize     = "x-amz-meta-encryption-chunk-size"
	MetaChunkCount    = "x-amz-meta-encryption-chunk-count"
	MetaManifest      = "x-amz-meta-encryption-manifest"
)

// ChunkManifest represents the encryption manifest for chunked objects.
// It stores the IV for each chunk, allowing decryption without reading
// the entire object first.
type ChunkManifest struct {
	Version    int      `json:"v"` // Format version (currently 1)
	ChunkSize  int      `json:"cs"` // Size of each chunk in bytes
	ChunkCount int      `json:"cc"` // Number of chunks
	BaseIV     string   `json:"iv"` // Base64-encoded base IV (for IV derivation)
	IVs        []string `json:"ivs,omitempty"` // Optional: explicit IVs per chunk (if baseIV not used)
}

// chunkedEncryptReader implements streaming encryption in chunks.
// Each chunk is encrypted independently with its own IV, allowing
// true streaming without buffering the entire object.
type chunkedEncryptReader struct {
	source       io.Reader
	aead         cipher.AEAD
	baseIV       []byte
	chunkSize    int
	buffer       []byte
	currentChunk []byte
	chunkIndex   int
	manifest     *ChunkManifest
	bufferPool   *BufferPool
	closed       bool
	err          error
}

// newChunkedEncryptReader creates a new chunked encryption reader.
// It generates a base IV and derives per-chunk IVs deterministically.
func newChunkedEncryptReader(source io.Reader, aead cipher.AEAD, baseIV []byte, chunkSize int, bufferPool *BufferPool) (*chunkedEncryptReader, *ChunkManifest) {
	if chunkSize < MinChunkSize {
		chunkSize = MinChunkSize
	}
	if chunkSize > MaxChunkSize {
		chunkSize = MaxChunkSize
	}

	manifest := &ChunkManifest{
		Version:   1,
		ChunkSize: chunkSize,
		BaseIV:    encodeBase64(baseIV),
	}

	return &chunkedEncryptReader{
		source:       source,
		aead:         aead,
		baseIV:       baseIV,
		chunkSize:    chunkSize,
		buffer:       make([]byte, chunkSize),
		currentChunk: nil,
		chunkIndex:   0,
		manifest:     manifest,
		bufferPool:   bufferPool,
	}, manifest
}

// deriveChunkIV derives an IV for a specific chunk index.
// We use a simple counter-based approach: XOR the base IV with chunk index.
// This ensures uniqueness while maintaining determinism.
func (r *chunkedEncryptReader) deriveChunkIV(chunkIndex int) []byte {
	iv := make([]byte, len(r.baseIV))
	copy(iv, r.baseIV)

	// XOR the last 4 bytes with chunk index to derive unique IV per chunk
	// This maintains security while allowing streaming
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, uint32(chunkIndex))

	for i := 0; i < 4 && i < len(iv); i++ {
		iv[len(iv)-1-i] ^= indexBytes[3-i]
	}

	return iv
}

// Read implements io.Reader for chunked encryption.
// It reads from source, encrypts in chunks, and returns encrypted data.
func (r *chunkedEncryptReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, io.EOF
	}
	if r.err != nil {
		return 0, r.err
	}

	totalRead := 0

	for len(p) > totalRead {
		// If we have encrypted data in currentChunk, return it
		if len(r.currentChunk) > 0 {
			n := copy(p[totalRead:], r.currentChunk)
			r.currentChunk = r.currentChunk[n:]
			totalRead += n
			continue
		}

		// Read next chunk from source
		n, err := io.ReadFull(r.source, r.buffer)
		if err == io.EOF {
			// No more data from source
			if n == 0 {
				// Nothing left to encrypt
				if totalRead > 0 {
					return totalRead, nil
				}
				r.closed = true
				return 0, io.EOF
			}
			// Partial chunk at end - still encrypt it
			r.encryptChunk(r.buffer[:n])
			if r.err != nil {
				return totalRead, r.err
			}
			continue
		}
		if err == io.ErrUnexpectedEOF {
			// Partial read - encrypt what we got
			r.encryptChunk(r.buffer[:n])
			if r.err != nil {
				return totalRead, r.err
			}
			continue
		}
		if err != nil {
			r.err = err
			return totalRead, err
		}

		// Encrypt the chunk
		r.encryptChunk(r.buffer[:n])
		if r.err != nil {
			return totalRead, r.err
		}
	}

	return totalRead, nil
}

// encryptChunk encrypts a single chunk of plaintext.
func (r *chunkedEncryptReader) encryptChunk(plaintext []byte) {
	if len(plaintext) == 0 {
		return
	}

	// Derive IV for this chunk
	chunkIV := r.deriveChunkIV(r.chunkIndex)

	// Encrypt the chunk
	ciphertext := r.aead.Seal(nil, chunkIV, plaintext, nil)

	// Store encrypted chunk for Read() to return
	r.currentChunk = append(r.currentChunk, ciphertext...)

	r.chunkIndex++
	r.manifest.ChunkCount++
}

// Close finalizes the encryption and returns the manifest.
func (r *chunkedEncryptReader) Close() error {
	r.closed = true
	return nil
}


// chunkedDecryptReader implements streaming decryption from chunked format.
type chunkedDecryptReader struct {
	source       io.Reader
	aead         cipher.AEAD
	manifest     *ChunkManifest
	baseIV       []byte
	chunkSize    int
	buffer       []byte
	currentChunk []byte
	chunkIndex   int
	bufferPool   *BufferPool
	closed       bool
	err          error
}

// newChunkedDecryptReader creates a new chunked decryption reader.
func newChunkedDecryptReader(source io.Reader, aead cipher.AEAD, manifest *ChunkManifest, bufferPool *BufferPool) (*chunkedDecryptReader, error) {
	baseIV, err := decodeBase64(manifest.BaseIV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base IV: %w", err)
	}

	return &chunkedDecryptReader{
		source:       source,
		aead:         aead,
		manifest:     manifest,
		baseIV:       baseIV,
		chunkSize:    manifest.ChunkSize,
		buffer:       make([]byte, manifest.ChunkSize+tagSize), // Account for auth tag
		currentChunk: nil,
		chunkIndex:   0,
		bufferPool:   bufferPool,
	}, nil
}

// deriveChunkIV derives an IV for a specific chunk (same as encryption).
func (r *chunkedDecryptReader) deriveChunkIV(chunkIndex int) []byte {
	iv := make([]byte, len(r.baseIV))
	copy(iv, r.baseIV)

	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, uint32(chunkIndex))

	for i := 0; i < 4 && i < len(iv); i++ {
		iv[len(iv)-1-i] ^= indexBytes[3-i]
	}

	return iv
}

// Read implements io.Reader for chunked decryption.
func (r *chunkedDecryptReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, io.EOF
	}
	if r.err != nil {
		return 0, r.err
	}

	totalRead := 0

	for len(p) > totalRead {
		// If we have decrypted data, return it
		if len(r.currentChunk) > 0 {
			n := copy(p[totalRead:], r.currentChunk)
			r.currentChunk = r.currentChunk[n:]
			totalRead += n
			continue
		}

		// Read next encrypted chunk from source
		// Each encrypted chunk is: plaintext_size + tagSize
		// For non-final chunks: chunkSize + tagSize
		// For final chunk: may be smaller
		expectedSize := r.chunkSize + tagSize
		maxRead := len(r.buffer)
		if expectedSize > maxRead {
			expectedSize = maxRead
		}

		n, err := io.ReadFull(r.source, r.buffer[:expectedSize])
		if err == io.EOF {
			if n == 0 {
				if totalRead > 0 {
					return totalRead, nil
				}
				r.closed = true
				return 0, io.EOF
			}
			// Partial read at end - try to decrypt
			r.decryptChunk(r.buffer[:n])
			if r.err != nil {
				return totalRead, r.err
			}
			continue
		}
		if err == io.ErrUnexpectedEOF {
			// Partial read - try to decrypt what we got (may be last chunk)
			r.decryptChunk(r.buffer[:n])
			if r.err != nil {
				return totalRead, r.err
			}
			continue
		}
		if err != nil {
			r.err = err
			return totalRead, err
		}

		// Decrypt the chunk
		r.decryptChunk(r.buffer[:n])
		if r.err != nil {
			return totalRead, r.err
		}
	}

	return totalRead, nil
}

// decryptChunk decrypts a single chunk of ciphertext.
func (r *chunkedDecryptReader) decryptChunk(ciphertext []byte) {
	if len(ciphertext) == 0 {
		return
	}

	// Derive IV for this chunk
	chunkIV := r.deriveChunkIV(r.chunkIndex)

	// Decrypt the chunk
	plaintext, err := r.aead.Open(nil, chunkIV, ciphertext, nil)
	if err != nil {
		r.err = fmt.Errorf("failed to decrypt chunk %d: %w", r.chunkIndex, err)
		return
	}

	// Store decrypted chunk for Read() to return
	r.currentChunk = append(r.currentChunk, plaintext...)

	r.chunkIndex++
}

// Close finalizes the decryption.
func (r *chunkedDecryptReader) Close() error {
	r.closed = true
	return nil
}

// encodeManifest encodes a chunk manifest to JSON for storage in metadata.
func encodeManifest(manifest *ChunkManifest) (string, error) {
	data, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("failed to encode manifest: %w", err)
	}
	return encodeBase64(data), nil
}

// decodeManifest decodes a chunk manifest from metadata.
func decodeManifest(encoded string) (*ChunkManifest, error) {
	data, err := decodeBase64(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode manifest: %w", err)
	}

	var manifest ChunkManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	return &manifest, nil
}

// IsChunkedFormat checks if metadata indicates chunked encryption format.
// This is exported for use by handlers to optimize range requests.
func IsChunkedFormat(metadata map[string]string) bool {
	if metadata == nil {
		return false
	}
	return metadata[MetaChunkedFormat] == "true"
}

// isChunkedFormat is the internal version (kept for backward compatibility).
func isChunkedFormat(metadata map[string]string) bool {
	return IsChunkedFormat(metadata)
}

// loadManifestFromMetadata loads chunk manifest from object metadata.
func loadManifestFromMetadata(metadata map[string]string) (*ChunkManifest, error) {
	manifestEncoded, ok := metadata[MetaManifest]
	if !ok {
		return nil, fmt.Errorf("manifest not found in metadata")
	}

	return decodeManifest(manifestEncoded)
}
