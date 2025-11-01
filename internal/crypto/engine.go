package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// Key derivation parameters
	pbkdf2Iterations = 100000
	aesKeySize       = 32 // 256 bits
	saltSize         = 32 // 256 bits
	nonceSize        = 12 // 96 bits for GCM
	tagSize          = 16 // 128 bits authentication tag

	// Metadata keys for encryption information
	MetaEncrypted          = "x-amz-meta-encrypted"
	MetaAlgorithm          = "x-amz-meta-encryption-algorithm"
	MetaKeySalt            = "x-amz-meta-encryption-key-salt"
	MetaIV                 = "x-amz-meta-encryption-iv"
	MetaAuthTag            = "x-amz-meta-encryption-auth-tag"
	MetaOriginalSize       = "x-amz-meta-encryption-original-size"
	MetaOriginalETag       = "x-amz-meta-encryption-original-etag"
	MetaCompression        = "x-amz-meta-encryption-compression"
	MetaCompressionEnabled = "x-amz-meta-compression-enabled"
	MetaCompressionAlgorithm = "x-amz-meta-compression-algorithm"
	MetaCompressionOriginalSize = "x-amz-meta-compression-original-size"

	// Algorithm name
	AlgorithmAES256GCM = "AES256-GCM"
)

// EncryptionEngine provides encryption and decryption functionality.
type EncryptionEngine interface {
	// Encrypt encrypts data from the reader and returns an encrypted reader
	// along with encryption metadata.
	Encrypt(reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error)

	// Decrypt decrypts data from the reader using the provided metadata
	// and returns a decrypted reader along with updated metadata.
	Decrypt(reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error)

	// IsEncrypted checks if the metadata indicates the object is encrypted.
	IsEncrypted(metadata map[string]string) bool
}

// engine implements the EncryptionEngine interface.
type engine struct {
	password          string
	compressionEngine CompressionEngine
}

// NewEngine creates a new encryption engine with the given password.
//
// The password is used to derive encryption keys using PBKDF2 with
// 100,000 iterations and a random salt per object.
func NewEngine(password string) (EncryptionEngine, error) {
	return NewEngineWithCompression(password, nil)
}

// NewEngineWithCompression creates a new encryption engine with compression support.
func NewEngineWithCompression(password string, compressionEngine CompressionEngine) (EncryptionEngine, error) {
	if password == "" {
		return nil, fmt.Errorf("encryption password cannot be empty")
	}

	if len(password) < 12 {
		return nil, fmt.Errorf("encryption password must be at least 12 characters")
	}

	// Log hardware acceleration info
	if HasAESHardwareSupport() {
		// Hardware acceleration is available (Go's crypto automatically uses it)
		// We could log this for monitoring purposes
	}

	return &engine{
		password:          password,
		compressionEngine: compressionEngine,
	}, nil
}

// deriveKey derives an AES-256 key from the password using PBKDF2.
func (e *engine) deriveKey(salt []byte) ([]byte, error) {
	if len(salt) != saltSize {
		return nil, fmt.Errorf("invalid salt size: expected %d bytes, got %d", saltSize, len(salt))
	}

	key := pbkdf2.Key([]byte(e.password), salt, pbkdf2Iterations, aesKeySize, sha256.New)
	return key, nil
}

// generateSalt generates a cryptographically secure random salt.
func (e *engine) generateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// generateNonce generates a cryptographically secure random nonce/IV.
func (e *engine) generateNonce() ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// createCipher creates an AES cipher for the given key.
func (e *engine) createCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return gcm, nil
}

// Encrypt encrypts data from the reader and returns an encrypted reader
// along with encryption metadata.
func (e *engine) Encrypt(reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	// Read the plaintext first to get size and content type (needed for compression decision)
	plaintext, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read plaintext: %w", err)
	}
	originalSize := int64(len(plaintext))

	// Extract content type from metadata
	contentType := ""
	if metadata != nil {
		contentType = metadata["Content-Type"]
	}

	// Compute original ETag from original (uncompressed) data
	// This must be done before compression potentially changes the data
	originalETag := computeETag(plaintext)

	// Apply compression if enabled and applicable
	var toEncrypt io.Reader = bytes.NewReader(plaintext)
	compressionMetadata := make(map[string]string)
	if e.compressionEngine != nil {
		compressedReader, compMeta, err := e.compressionEngine.Compress(bytes.NewReader(plaintext), contentType, originalSize)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to compress data: %w", err)
		}
		if compMeta != nil {
			// Compression was applied and was beneficial
			compressionMetadata = compMeta
			// Read compressed data
			compressedData, err := io.ReadAll(compressedReader)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read compressed data: %w", err)
			}
			toEncrypt = bytes.NewReader(compressedData)
		}
		// If compression wasn't applied, compMeta will be nil and we continue with original
	}

	// Generate salt and nonce for this encryption
	salt, err := e.generateSalt()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	nonce, err := e.generateNonce()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Derive key from password and salt
	key, err := e.deriveKey(salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer zeroBytes(key)

	// Create GCM cipher
	gcm, err := e.createCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Read data to encrypt (may be compressed)
	dataToEncrypt, err := io.ReadAll(toEncrypt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read data for encryption: %w", err)
	}

	// Encrypt the data using GCM
	ciphertext := gcm.Seal(nil, nonce, dataToEncrypt, nil)

	// Create encrypted reader from ciphertext
	encryptedReader := bytes.NewReader(ciphertext)

	// Prepare encryption metadata
	encMetadata := make(map[string]string)
	if metadata != nil {
		// Copy original metadata
		for k, v := range metadata {
			encMetadata[k] = v
		}
	}

	// Merge compression metadata if compression was applied
	if compressionMetadata != nil {
		for k, v := range compressionMetadata {
			encMetadata[k] = v
		}
	}

	// Add encryption markers
	encMetadata[MetaEncrypted] = "true"
	encMetadata[MetaAlgorithm] = AlgorithmAES256GCM
	encMetadata[MetaKeySalt] = encodeBase64(salt)
	encMetadata[MetaIV] = encodeBase64(nonce)
	encMetadata[MetaOriginalSize] = fmt.Sprintf("%d", originalSize)
	encMetadata[MetaOriginalETag] = originalETag

	// Note: Authentication tag is included in the ciphertext by GCM.Seal

	return encryptedReader, encMetadata, nil
}

// Decrypt decrypts data from the reader using the provided metadata
// and returns a decrypted reader along with updated metadata.
func (e *engine) Decrypt(reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	if !e.IsEncrypted(metadata) {
		// Not encrypted, return as-is
		return reader, metadata, nil
	}

	// Extract encryption parameters from metadata
	salt, err := decodeBase64(metadata[MetaKeySalt])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	iv, err := decodeBase64(metadata[MetaIV])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	// Derive key from password and salt
	key, err := e.deriveKey(salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer zeroBytes(key)

	// Create GCM cipher
	gcm, err := e.createCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create decrypted reader
	decryptedReader, err := newDecryptReader(reader, gcm, iv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create decrypt reader: %w", err)
	}

	// Read decrypted data (may be compressed)
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	// Apply decompression if compression was used
	var finalReader io.Reader = bytes.NewReader(decryptedData)
	if e.compressionEngine != nil {
		decompressedReader, err := e.compressionEngine.Decompress(bytes.NewReader(decryptedData), metadata)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decompress data: %w", err)
		}
		finalReader = decompressedReader
	}

	// Prepare decrypted metadata (remove encryption and compression markers)
	decMetadata := make(map[string]string)
	for k, v := range metadata {
		// Skip encryption-related and compression-related metadata
		if isEncryptionMetadata(k) || isCompressionMetadata(k) {
			continue
		}
		decMetadata[k] = v
	}

	// Restore original size if available
	if originalSize, ok := metadata[MetaOriginalSize]; ok {
		decMetadata["Content-Length"] = originalSize
	}

	// Restore original ETag if available
	if originalETag, ok := metadata[MetaOriginalETag]; ok {
		decMetadata["ETag"] = originalETag
	}

	return finalReader, decMetadata, nil
}

// IsEncrypted checks if the metadata indicates the object is encrypted.
func (e *engine) IsEncrypted(metadata map[string]string) bool {
	if metadata == nil {
		return false
	}

	encrypted, ok := metadata[MetaEncrypted]
	return ok && encrypted == "true"
}

// computeETag computes the ETag (MD5 hash) for the given data.
// S3 typically uses MD5 hash as ETag for objects.
func computeETag(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

// isEncryptionMetadata checks if a metadata key is related to encryption.
func isEncryptionMetadata(key string) bool {
	return key == MetaEncrypted ||
		key == MetaAlgorithm ||
		key == MetaKeySalt ||
		key == MetaIV ||
		key == MetaAuthTag ||
		key == MetaOriginalSize ||
		key == MetaOriginalETag
}

// isCompressionMetadata checks if a metadata key is related to compression.
func isCompressionMetadata(key string) bool {
	return key == MetaCompression ||
		key == MetaCompressionEnabled ||
		key == MetaCompressionAlgorithm ||
		key == MetaCompressionOriginalSize
}

// zeroBytes overwrites a byte slice with zeros for secure memory cleanup.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
