# Encryption System Design

## Overview

The encryption system provides client-side encryption/decryption for all S3 objects passing through the gateway. It uses authenticated encryption to ensure both confidentiality and integrity of data.

## Encryption Algorithms

- AES-256-GCM (default)
- ChaCha20-Poly1305 (supported in later phases; selectable via configuration)

### AES-256-GCM

### Why AES-256-GCM?
- **Authenticated encryption**: Provides both confidentiality and integrity
- **Industry standard**: Widely adopted and vetted
- **Performance**: Hardware-accelerated on modern CPUs
- **No padding issues**: GCM handles variable-length data efficiently
- **Nonce-based**: No counter state to maintain

### AES-256-GCM Details
- **Key size**: 256 bits (32 bytes)
- **Block size**: 128 bits (16 bytes)
- **Authentication tag**: 128 bits (16 bytes)
- **Nonce/IV size**: 96 bits (12 bytes) - GCM standard

## Key Derivation

### PBKDF2 Key Derivation
```go
func deriveKey(password string, salt []byte) []byte {
    return pbkdf2.Key([]byte(password), salt, iterations, keyLen, sha256.New)
}
```

### Parameters
- **Password**: User-provided encryption password
- **Salt**: 32-byte random salt per object
- **Iterations**: 100,000 (balance between security and performance)
- **Hash function**: SHA-256
- **Output length**: 32 bytes (AES-256 key)

### Salt Generation
- **Per-object salt**: Ensures unique key per object
- **Random generation**: Cryptographically secure random bytes
- **Storage**: Stored in object metadata

## Encryption Process

### Data Format
```
Encrypted Object = Salt + IV + Encrypted Data + Authentication Tag
```

### Step-by-Step Encryption (AES-256-GCM)
1. **Generate salt**: 32 bytes of random data
2. **Derive key**: PBKDF2(password, salt, 100000, 32, SHA256)
3. **Generate IV**: 12 bytes of random data
4. **Initialize GCM**: cipher.NewGCM(cipher)
5. **Encrypt**: ciphertext, tag := GCM.Seal(nil, iv, plaintext, nil)
6. **Assemble**: salt + iv + ciphertext + tag
7. **Store metadata**: encryption info in S3 metadata

### Encryption Metadata
```json
{
  "encrypted": true,
  "algorithm": "AES256-GCM",
  "key_salt": "base64-encoded-32-byte-salt",
  "iv": "base64-encoded-12-byte-iv",
  "auth_tag": "base64-encoded-16-byte-tag",
  "original_size": 12345,
  "original_etag": "original-etag-hex",
  "compression": "none"
}
```

## Decryption Process

### Step-by-Step Decryption (AES-256-GCM)
1. **Extract metadata**: Read encryption info from S3 metadata
2. **Verify encryption**: Check "encrypted" flag
3. **Derive key**: Same PBKDF2 process with stored salt
4. **Extract components**: Parse salt, IV, ciphertext, tag
5. **Initialize GCM**: cipher.NewGCM(cipher)
6. **Decrypt**: plaintext, err := GCM.Open(nil, iv, ciphertext, nil)
7. **Verify integrity**: GCM handles authentication automatically
8. **Return data**: Original plaintext

### Error Handling
- **Invalid password**: Decryption will fail with authentication error
- **Corrupted data**: GCM will detect and return error
- **Missing metadata**: Assume unencrypted, pass through
- **Wrong algorithm**: Return error for unsupported algorithms

## Streaming Implementation

### EncryptReader
```go
type EncryptReader struct {
    source  io.Reader
    cipher  cipher.AEAD
    buffer  []byte
    iv      []byte
    salt    []byte
}

func (r *EncryptReader) Read(p []byte) (n int, err error) {
    // Read from source
    // Encrypt in chunks
    // Return encrypted data
}
```

### DecryptReader
```go
type DecryptReader struct {
    source  io.Reader
    cipher  cipher.AEAD
    buffer  []byte
    iv      []byte
}

func (r *DecryptReader) Read(p []byte) (n int, err error) {
    // Read encrypted chunks
    // Decrypt and return
}
```

### Memory Management
- **Chunk size**: 64KB for balanced memory/performance
- **Buffer pooling**: Reuse buffers to reduce allocations
- **Large objects**: Stream processing prevents memory exhaustion
- **Small objects**: Buffer entire object if < 1MB

## Key Management

### Password-Based Security
- **User responsibility**: Secure password storage and distribution
- **No key storage**: Keys derived at runtime, never stored
- **Password requirements**: Minimum 12 characters, complexity encouraged

### Future Key Management Service (KMS) Support
- **Interface design**: Pluggable key providers
- **AWS KMS**: Integration with cloud KMS
- **HashiCorp Vault**: Enterprise key management
- **Local KMS**: File-based key storage for development

## Security Considerations

### Cryptographic Security
- **Algorithm security**: AES-256-GCM is quantum-resistant for confidentiality
- **Key derivation**: PBKDF2 provides protection against brute force
- **IV uniqueness**: Random IV per object prevents reuse attacks
- **Authentication**: GCM prevents tampering and ensures integrity

### Operational Security
- **Memory safety**: Keys and plaintext don't persist in memory longer than needed
- **Secure deletion**: Overwrite sensitive data before freeing
- **Audit logging**: Log encryption operations without exposing keys
- **Access controls**: Restrict gateway access to authorized users

### Performance vs Security Trade-offs
- **PBKDF2 iterations**: 100,000 provides good security with acceptable performance
- **Hardware acceleration**: Leverage AES-NI instructions when available
- **Concurrent processing**: Multiple goroutines for parallel encryption

## Metadata Handling

### S3 Metadata Strategy
- **Encryption markers**: Clear indicators of encrypted objects
- **Original preservation**: Store original metadata for restoration
- **Size tracking**: Track original vs encrypted sizes
- **ETag handling**: Store original ETag, provide encrypted ETag to clients

### Metadata Keys
```go
const (
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
```

### Client Response Filtering
- **Hide encryption metadata**: Don't expose internal encryption details
- **Restore original metadata**: Show original Content-Type, ETag, etc.
- **Size reporting**: Report original object size, not encrypted size

## Compression Integration

### Pre-Encryption Compression (Optional)
- **Configurable**: Can be enabled/disabled based on performance requirements
- **Algorithm**: gzip (most compatible, good compression ratio)
- **When to compress**: Objects > 1KB, compressible content types (text, JSON, XML, etc.)
- **Metadata tracking**: Store compression status and algorithm
- **Decompression**: Automatic on decryption when compression was used
- **Performance trade-off**: ~2-3x slower but saves bandwidth/storage

### Configuration
```go
type CompressionConfig struct {
    Enabled         bool     `yaml:"enabled" env:"COMPRESSION_ENABLED"`
    MinSize         int64    `yaml:"min_size" env:"COMPRESSION_MIN_SIZE"` // Minimum object size to compress
    ContentTypes    []string `yaml:"content_types"` // Content types to compress
    Algorithm       string   `yaml:"algorithm"`     // "gzip", "zstd", etc.
    Level           int      `yaml:"level"`         // Compression level (1-9)
}
```

### Implementation
```go
type CompressionEngine interface {
    Compress(reader io.Reader, contentType string) (io.Reader, *CompressionMetadata, error)
    Decompress(reader io.Reader, metadata *CompressionMetadata) (io.Reader, error)
    ShouldCompress(size int64, contentType string) bool
}

type CompressionMetadata struct {
    Algorithm   string `json:"algorithm"`
    OriginalSize int64  `json:"original_size"`
    CompressedSize int64 `json:"compressed_size"`
}
```

## Performance Optimizations

### Hardware Acceleration
- **AES-NI**: Detect and use hardware AES instructions
- **Parallel processing**: Encrypt/decrypt multiple chunks concurrently
- **Buffer alignment**: Align buffers for optimal crypto performance

### Caching Considerations
- **Key caching**: Cache derived keys for same password/salt combinations
- **Session-based**: Cache keys per encryption session
- **Memory limits**: Bound cache size to prevent memory leaks

### Benchmarking Targets
- **Encryption speed**: > 100 MB/s on modern hardware
- **Decryption speed**: > 100 MB/s on modern hardware
- **Latency overhead**: < 10ms for small objects
- **Memory usage**: < 50MB per concurrent encryption

## Testing and Validation

### Unit Tests
- **Algorithm correctness**: Test vectors from NIST
- **Key derivation**: Validate PBKDF2 implementation
- **Streaming**: Test chunked encryption/decryption
- **Error cases**: Invalid passwords, corrupted data

### Integration Tests
- **Round-trip encryption**: Encrypt ? Decrypt ? Verify identical
- **Large files**: Test with multi-gigabyte objects
- **Concurrent operations**: Test multiple encryptions simultaneously
- **Memory leaks**: Profile memory usage under load

### Security Testing
- **Known plaintext attacks**: Test resistance to cryptanalysis
- **Side-channel analysis**: Timing attack resistance
- **Key leakage**: Ensure keys don't leak in logs or errors
- **Compliance**: Validate against security standards

## Future Extensions

### Additional Algorithms
- **ChaCha20-Poly1305**: Alternative authenticated encryption
- **AES-256-CBC**: Legacy compatibility (with HMAC)
- **Age encryption**: Modern alternative to GPG

### Advanced Features
- **Key rotation**: Support for changing encryption keys
- **Envelope encryption**: Encrypt data keys with master keys
- **Client-side key derivation**: Allow clients to provide derived keys
- **Multi-key encryption**: Support multiple passwords per object

### Enterprise Features
- **KMS integration**: AWS KMS, Azure Key Vault, GCP KMS
- **Key versioning**: Support for key rotation and versioning
- **Access auditing**: Detailed encryption/decryption logs
- **Compliance reporting**: Generate reports for regulatory compliance

## Implementation Roadmap

### Phase 1: Core Encryption
- AES-256-GCM implementation
- PBKDF2 key derivation
- Basic streaming encrypt/decrypt
- Metadata handling

### Phase 2: Performance & Security
- Hardware acceleration detection
- Buffer pooling and optimization
- Comprehensive security testing
- Memory safety improvements

### Phase 3: Advanced Features
- Compression integration
- Multiple algorithm support
- KMS integration interfaces
- Key rotation support

### Phase 4: Enterprise Features
- Audit logging
- Compliance reporting
- Advanced key management
- Performance monitoring