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
	preferredAlgorithm string
	supportedAlgorithms []string
    // keyResolver resolves a password by key version for decryption of older objects
    keyResolver       func(version int) (string, bool)
	// Chunked encryption settings
	chunkedMode bool // Enable chunked/streaming encryption mode
	chunkSize    int  // Size of each encryption chunk (default: DefaultChunkSize)
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
	return NewEngineWithOptions(password, compressionEngine, "", nil)
}

// NewEngineWithOptions creates a new encryption engine with full options.
func NewEngineWithOptions(password string, compressionEngine CompressionEngine, preferredAlgorithm string, supportedAlgorithms []string) (EncryptionEngine, error) {
	return NewEngineWithChunking(password, compressionEngine, preferredAlgorithm, supportedAlgorithms, true, DefaultChunkSize)
}

// NewEngineWithChunking creates a new encryption engine with chunked mode support.
func NewEngineWithChunking(password string, compressionEngine CompressionEngine, preferredAlgorithm string, supportedAlgorithms []string, chunkedMode bool, chunkSize int) (EncryptionEngine, error) {
	if password == "" {
		return nil, fmt.Errorf("encryption password cannot be empty")
	}

	if len(password) < 12 {
		return nil, fmt.Errorf("encryption password must be at least 12 characters")
	}

	// Default algorithm configuration
	if preferredAlgorithm == "" {
		preferredAlgorithm = AlgorithmAES256GCM
	}
	
	if len(supportedAlgorithms) == 0 {
		supportedAlgorithms = []string{AlgorithmAES256GCM, AlgorithmChaCha20Poly1305}
	}

	// Validate preferred algorithm
	if !isAlgorithmSupported(preferredAlgorithm, supportedAlgorithms) {
		return nil, fmt.Errorf("preferred algorithm %s is not in supported algorithms list", preferredAlgorithm)
	}

	// Validate and set chunk size
	if chunkSize == 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize < MinChunkSize {
		chunkSize = MinChunkSize
	}
	if chunkSize > MaxChunkSize {
		chunkSize = MaxChunkSize
	}

	// Log hardware acceleration info
	if HasAESHardwareSupport() {
		// Hardware acceleration is available (Go's crypto automatically uses it)
		// We could log this for monitoring purposes
	}

	return &engine{
		password:           password,
		compressionEngine:  compressionEngine,
		preferredAlgorithm: preferredAlgorithm,
		supportedAlgorithms: supportedAlgorithms,
		chunkedMode:         chunkedMode,
		chunkSize:            chunkSize,
	}, nil
}

// NewEngineWithResolver creates a new encryption engine with a key resolver for rotation support.
func NewEngineWithResolver(password string, compressionEngine CompressionEngine, preferredAlgorithm string, supportedAlgorithms []string, resolver func(version int) (string, bool)) (EncryptionEngine, error) {
    eng, err := NewEngineWithOptions(password, compressionEngine, preferredAlgorithm, supportedAlgorithms)
    if err != nil {
        return nil, err
    }
    // Set resolver on concrete type
    if e, ok := eng.(*engine); ok {
        e.keyResolver = resolver
    }
    return eng, nil
}

// SetKeyResolver sets a key resolver on an existing engine instance.
// This allows decryption using older key versions without reconstructing the engine.
func SetKeyResolver(enc EncryptionEngine, resolver func(version int) (string, bool)) {
    if e, ok := enc.(*engine); ok {
        e.keyResolver = resolver
    }
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
	return e.generateNonceForAlgorithm(e.preferredAlgorithm)
}

// generateNonceForAlgorithm generates a nonce with the correct size for the algorithm.
func (e *engine) generateNonceForAlgorithm(algorithm string) ([]byte, error) {
	nonceSize, err := getNonceSize(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce size for algorithm %s: %w", algorithm, err)
	}
	
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
	// If chunked mode is enabled, use streaming chunked encryption
	if e.chunkedMode {
		return e.encryptChunked(reader, metadata)
	}

	// Legacy buffered mode for backward compatibility
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

	// Determine algorithm to use (preferred algorithm for new encryptions)
	algorithm := e.preferredAlgorithm

	// Generate salt and nonce for this encryption
	salt, err := e.generateSalt()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	nonce, err := e.generateNonceForAlgorithm(algorithm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Derive key from password and salt
	key, err := e.deriveKey(salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer zeroBytes(key)

	// Use appropriate key size for algorithm
	keySize := aesKeySize
	if algorithm == AlgorithmChaCha20Poly1305 {
		keySize = chacha20KeySize
	}
	if len(key) != keySize {
		// Trim or pad key to required size
		adjustedKey := make([]byte, keySize)
		copy(adjustedKey, key)
		if len(key) < keySize {
			// Pad with PBKDF2 of original key (simple approach)
			copy(adjustedKey[len(key):], key[:keySize-len(key)])
		}
		zeroBytes(key)
		key = adjustedKey
	}

	// Create cipher using selected algorithm
	aeadCipher, err := createAEADCipher(algorithm, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher for algorithm %s: %w", algorithm, err)
	}
	gcm := aeadCipher.(cipher.AEAD) // For backward compatibility with existing code

	// Read data to encrypt (may be compressed)
	dataToEncrypt, err := io.ReadAll(toEncrypt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read data for encryption: %w", err)
	}

    // Build AAD to bind critical metadata
    aad := buildAAD(algorithm, salt, nonce, map[string]string{
        "Content-Type": contentType,
        MetaKeyVersion:  metadata[MetaKeyVersion],
        MetaOriginalSize: fmt.Sprintf("%d", originalSize),
    })
    // Encrypt the data using AEAD with AAD
    ciphertext := gcm.Seal(nil, nonce, dataToEncrypt, aad)

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
	encMetadata[MetaAlgorithm] = algorithm
	encMetadata[MetaKeySalt] = encodeBase64(salt)
	encMetadata[MetaIV] = encodeBase64(nonce)
	encMetadata[MetaOriginalSize] = fmt.Sprintf("%d", originalSize)
	encMetadata[MetaOriginalETag] = originalETag
    // Preserve key version if provided by caller
    if kv, ok := metadata[MetaKeyVersion]; ok && kv != "" {
        encMetadata[MetaKeyVersion] = kv
    }

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

	// Check if this is chunked format
	if isChunkedFormat(metadata) {
		return e.decryptChunked(reader, metadata)
	}

	// Legacy buffered mode for backward compatibility

	// Extract encryption parameters from metadata
	salt, err := decodeBase64(metadata[MetaKeySalt])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	iv, err := decodeBase64(metadata[MetaIV])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	// Get algorithm from metadata (default to AES-GCM for backward compatibility)
	algorithm := metadata[MetaAlgorithm]
	if algorithm == "" {
		algorithm = AlgorithmAES256GCM
	}

	// Verify algorithm is supported
	if !isAlgorithmSupported(algorithm, e.supportedAlgorithms) {
		return nil, nil, fmt.Errorf("unsupported algorithm %s (not in supported list)", algorithm)
	}

	// Derive key from password and salt
	key, err := e.deriveKey(salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer zeroBytes(key)

	// Adjust key size for algorithm
	keySize := aesKeySize
	if algorithm == AlgorithmChaCha20Poly1305 {
		keySize = chacha20KeySize
	}
	if len(key) != keySize {
		adjustedKey := make([]byte, keySize)
		copy(adjustedKey, key)
		if len(key) < keySize {
			copy(adjustedKey[len(key):], key[:keySize-len(key)])
		}
		zeroBytes(key)
		key = adjustedKey
	}

	// Create cipher using algorithm from metadata
	aeadCipher, err := createAEADCipher(algorithm, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher for algorithm %s: %w", algorithm, err)
	}
	gcm := aeadCipher.(cipher.AEAD) // For backward compatibility

    // Read all encrypted data (current implementation is buffered)
    ciphertext, err := io.ReadAll(reader)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to read encrypted data: %w", err)
    }

    // Build AAD from metadata
    aad := buildAAD(algorithm, salt, iv, map[string]string{
        MetaKeyVersion:  metadata[MetaKeyVersion],
        MetaOriginalSize: metadata[MetaOriginalSize],
        "Content-Type":  metadata["Content-Type"],
    })

    // Attempt decrypt with current key and AAD
    plaintext, openErr := gcm.Open(nil, iv, ciphertext, aad)
    if openErr != nil {
        // Backward compatibility: try without AAD
        if pt, err2 := gcm.Open(nil, iv, ciphertext, nil); err2 == nil {
            plaintext = pt
            openErr = nil
        }
    }

    // If still failing and keyResolver available with key version, try resolved password
    if openErr != nil && e.keyResolver != nil {
        if kvStr, ok := metadata[MetaKeyVersion]; ok && kvStr != "" {
            // parse version
            var ver int
            if _, perr := fmt.Sscanf(kvStr, "%d", &ver); perr == nil {
                if altPass, ok := e.keyResolver(ver); ok {
                    // derive alt key
                    altKey := pbkdf2.Key([]byte(altPass), salt, pbkdf2Iterations, keySize, sha256.New)
                    defer zeroBytes(altKey)
                    // create cipher
                    altCipher, cerr := createAEADCipher(algorithm, altKey)
                    if cerr == nil {
                        altGCM := altCipher.(cipher.AEAD)
                        if pt, err3 := altGCM.Open(nil, iv, ciphertext, aad); err3 == nil {
                            plaintext = pt
                            openErr = nil
                        } else if pt2, err4 := altGCM.Open(nil, iv, ciphertext, nil); err4 == nil {
                            plaintext = pt2
                            openErr = nil
                        }
                    }
                }
            }
        }
    }

    if openErr != nil {
        return nil, nil, fmt.Errorf("failed to decrypt data: %w", openErr)
    }

    // Create decrypted reader from plaintext
    decryptedReader := bytes.NewReader(plaintext)

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

// encryptChunked implements streaming chunked encryption.
func (e *engine) encryptChunked(reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	// Determine algorithm to use
	algorithm := e.preferredAlgorithm

	// Generate salt and base IV for this encryption
	salt, err := e.generateSalt()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	baseIV, err := e.generateNonceForAlgorithm(algorithm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate base IV: %w", err)
	}

	// Derive key from password and salt
	key, err := e.deriveKey(salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer zeroBytes(key)

	// Use appropriate key size for algorithm
	keySize := aesKeySize
	if algorithm == AlgorithmChaCha20Poly1305 {
		keySize = chacha20KeySize
	}
	if len(key) != keySize {
		adjustedKey := make([]byte, keySize)
		copy(adjustedKey, key)
		if len(key) < keySize {
			copy(adjustedKey[len(key):], key[:keySize-len(key)])
		}
		zeroBytes(key)
		key = adjustedKey
	}

	// Create cipher using selected algorithm
	aeadCipher, err := createAEADCipher(algorithm, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher for algorithm %s: %w", algorithm, err)
	}
	aead := aeadCipher.(cipher.AEAD)

	// Create chunked encrypt reader
	chunkedReader, manifest := newChunkedEncryptReader(reader, aead, baseIV, e.chunkSize)

	// Encode manifest for storage
	manifestEncoded, err := encodeManifest(manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode manifest: %w", err)
	}

	// Prepare encryption metadata
	encMetadata := make(map[string]string)
	if metadata != nil {
		// Copy original metadata
		for k, v := range metadata {
			encMetadata[k] = v
		}
	}

	// Add chunked encryption markers
	encMetadata[MetaEncrypted] = "true"
	encMetadata[MetaChunkedFormat] = "true"
	encMetadata[MetaAlgorithm] = algorithm
	encMetadata[MetaKeySalt] = encodeBase64(salt)
	encMetadata[MetaIV] = encodeBase64(baseIV)
	encMetadata[MetaChunkSize] = fmt.Sprintf("%d", e.chunkSize)
	encMetadata[MetaManifest] = manifestEncoded
	// Note: MetaChunkCount is NOT set here because manifest.ChunkCount is 0 at this point
	// (it only gets incremented during encryption). ChunkCount can be calculated during
	// decryption from the encrypted object size and chunk size, or from the manifest if needed.
	// Some S3 implementations reject metadata with value "0", so we omit it.
	// Preserve key version if provided
	if kv, ok := metadata[MetaKeyVersion]; ok && kv != "" {
		encMetadata[MetaKeyVersion] = kv
	}

	return chunkedReader, encMetadata, nil
}

// decryptChunked implements streaming chunked decryption.
func (e *engine) decryptChunked(reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	// Load manifest from metadata
	manifest, err := loadManifestFromMetadata(metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load manifest: %w", err)
	}

	// Extract encryption parameters from metadata
	salt, err := decodeBase64(metadata[MetaKeySalt])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	// Get algorithm from metadata (default to AES-GCM for backward compatibility)
	algorithm := metadata[MetaAlgorithm]
	if algorithm == "" {
		algorithm = AlgorithmAES256GCM
	}

	// Verify algorithm is supported
	if !isAlgorithmSupported(algorithm, e.supportedAlgorithms) {
		return nil, nil, fmt.Errorf("unsupported algorithm %s (not in supported list)", algorithm)
	}

	// Derive key from password and salt
	key, err := e.deriveKey(salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer zeroBytes(key)

	// Adjust key size for algorithm
	keySize := aesKeySize
	if algorithm == AlgorithmChaCha20Poly1305 {
		keySize = chacha20KeySize
	}
	if len(key) != keySize {
		adjustedKey := make([]byte, keySize)
		copy(adjustedKey, key)
		if len(key) < keySize {
			copy(adjustedKey[len(key):], key[:keySize-len(key)])
		}
		zeroBytes(key)
		key = adjustedKey
	}

	// Create cipher using algorithm from metadata
	aeadCipher, err := createAEADCipher(algorithm, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher for algorithm %s: %w", algorithm, err)
	}
	aead := aeadCipher.(cipher.AEAD)

	// Create chunked decrypt reader
	chunkedReader, err := newChunkedDecryptReader(reader, aead, manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create chunked decrypt reader: %w", err)
	}

	// Prepare decrypted metadata (remove encryption markers)
	decMetadata := make(map[string]string)
	for k, v := range metadata {
		// Skip encryption-related metadata
		if isEncryptionMetadata(k) {
			continue
		}
		decMetadata[k] = v
	}

	// Restore original size if available
	if chunkCount, ok := metadata[MetaChunkCount]; ok {
		if chunkSize, ok2 := metadata[MetaChunkSize]; ok2 {
			var count, size int
			if _, err1 := fmt.Sscanf(chunkCount, "%d", &count); err1 == nil {
				if _, err2 := fmt.Sscanf(chunkSize, "%d", &size); err2 == nil {
					// Approximate original size (last chunk might be smaller)
					approxSize := int64((count - 1) * size + size)
					decMetadata["Content-Length"] = fmt.Sprintf("%d", approxSize)
				}
			}
		}
	}

	return chunkedReader, decMetadata, nil
}

// DecryptRange decrypts only the chunks needed for a specific plaintext range.
// This optimizes range requests by decrypting only necessary chunks.
func (e *engine) DecryptRange(reader io.Reader, metadata map[string]string, plaintextStart, plaintextEnd int64) (io.Reader, map[string]string, error) {
	if !e.IsEncrypted(metadata) {
		return nil, nil, fmt.Errorf("object is not encrypted")
	}

	// Only supports chunked format for range optimization
	if !isChunkedFormat(metadata) {
		return nil, nil, fmt.Errorf("range optimization only supported for chunked format")
	}

	// Load manifest
	manifest, err := loadManifestFromMetadata(metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load manifest: %w", err)
	}

	// Extract encryption parameters
	salt, err := decodeBase64(metadata[MetaKeySalt])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	baseIV, err := decodeBase64(metadata[MetaIV])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode base IV: %w", err)
	}

	// Get algorithm from metadata
	algorithm := metadata[MetaAlgorithm]
	if algorithm == "" {
		algorithm = AlgorithmAES256GCM
	}

	// Verify algorithm is supported
	if !isAlgorithmSupported(algorithm, e.supportedAlgorithms) {
		return nil, nil, fmt.Errorf("unsupported algorithm %s", algorithm)
	}

	// Derive key from password and salt
	key, err := e.deriveKey(salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer zeroBytes(key)

	// Adjust key size for algorithm
	keySize := aesKeySize
	if algorithm == AlgorithmChaCha20Poly1305 {
		keySize = chacha20KeySize
	}
	if len(key) != keySize {
		adjustedKey := make([]byte, keySize)
		copy(adjustedKey, key)
		if len(key) < keySize {
			copy(adjustedKey[len(key):], key[:keySize-len(key)])
		}
		zeroBytes(key)
		key = adjustedKey
	}

	// Create cipher
	aeadCipher, err := createAEADCipher(algorithm, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	aead := aeadCipher.(cipher.AEAD)

	// Create range-aware decrypt reader
	rangeReader, err := newRangeDecryptReader(reader, aead, manifest, baseIV, plaintextStart, plaintextEnd)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create range reader: %w", err)
	}

	// Prepare decrypted metadata
	decMetadata := make(map[string]string)
	for k, v := range metadata {
		if isEncryptionMetadata(k) {
			continue
		}
		decMetadata[k] = v
	}

	// Set Content-Length to the range size
	rangeSize := plaintextEnd - plaintextStart + 1
	decMetadata["Content-Length"] = fmt.Sprintf("%d", rangeSize)

	return rangeReader, decMetadata, nil
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
		key == MetaOriginalETag ||
		key == MetaChunkedFormat ||
		key == MetaChunkSize ||
		key == MetaChunkCount ||
		key == MetaManifest ||
		key == MetaKeyVersion
}

// isCompressionMetadata checks if a metadata key is related to compression.
func isCompressionMetadata(key string) bool {
	return key == MetaCompression ||
		key == MetaCompressionEnabled ||
		key == MetaCompressionAlgorithm ||
		key == MetaCompressionOriginalSize
}

// buildAAD constructs additional authenticated data from stable metadata fields.
// Fields included: algorithm, salt, nonce, keyVersion (if present), content-type (if present), original-size (if present).
func buildAAD(algorithm string, salt, nonce []byte, meta map[string]string) []byte {
    // Use a simple canonical concatenation with separators.
    // Note: All values must be stable between encrypt/decrypt.
    var b bytes.Buffer
    b.WriteString("alg:")
    b.WriteString(algorithm)
    b.WriteString("|salt:")
    b.WriteString(encodeBase64(salt))
    b.WriteString("|iv:")
    b.WriteString(encodeBase64(nonce))
    if kv := meta[MetaKeyVersion]; kv != "" {
        b.WriteString("|kv:")
        b.WriteString(kv)
    }
    if ct := meta["Content-Type"]; ct != "" {
        b.WriteString("|ct:")
        b.WriteString(ct)
    }
    if osz := meta[MetaOriginalSize]; osz != "" {
        b.WriteString("|osz:")
        b.WriteString(osz)
    }
    return b.Bytes()
}

// zeroBytes overwrites a byte slice with zeros for secure memory cleanup.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
