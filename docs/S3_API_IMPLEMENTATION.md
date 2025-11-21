# S3 API Implementation Strategy

## Overview

The S3 Encryption Gateway must maintain full compatibility with the Amazon S3 API while transparently encrypting and decrypting object data. This document outlines the implementation strategy for S3 API compatibility.

## S3 API Operations Classification

### Operations Requiring Encryption/Decryption

#### PUT Object
- **Endpoint**: `PUT /{bucket}/{key}`
- **Encryption**: Required for object data
- **Implementation**:
  - Parse request body as stream
  - Encrypt data using configured algorithm
  - Preserve original metadata
  - Add encryption metadata markers
  - Forward to backend with encrypted data

#### GET Object
- **Endpoint**: `GET /{bucket}/{key}`
- **Decryption**: Required for object data
- **Implementation**:
  - Check if object is encrypted (metadata marker)
  - Fetch encrypted data from backend
  - Decrypt data stream
  - Restore original metadata
  - Return decrypted response

#### POST Object (Multipart Upload)
- **Endpoints**:
  - `POST /{bucket}/{key}?uploads` - Initiate multipart upload
  - `PUT /{bucket}/{key}?partNumber=X&uploadId=Y` - Upload part
  - `POST /{bucket}/{key}?uploadId=Y` - Complete multipart upload
- **Encryption**: NOT applied (parts stored unencrypted)
- **Implementation**:
  - Parts are forwarded to backend without encryption to avoid concatenation issues
  - Preserve ordering and part ETags
  - Complete uploads by passing part list to backend
  - Multipart uploads bypass encryption for S3 provider compatibility
- **Security Considerations**:
  - **Multipart uploads are not encrypted** due to fundamental architectural limitations
  - Each part cannot be encrypted individually because S3 concatenates parts server-side
  - Encrypting parts separately creates multiple invalid encrypted streams when combined
  - For encrypted multipart uploads, use client-side encryption before sending to the gateway
- **Security Features (V0.4)**:
  - Robust XML parsing with 10MB size limits to prevent DoS
  - Comprehensive validation of part numbers (1-10000 range)
  - ETag format validation with proper quoting requirements
  - Duplicate part number detection and rejection
  - Fuzz-tested XML parser for edge case handling
  - Provider interoperability testing framework

#### PUT Object Copy
- **Endpoint**: `PUT /{bucket}/{key}?x-amz-copy-source=...`
- **Encryption**: Conditional based on source encryption status
- **Implementation**:
  - Check if source object is encrypted
  - Copy operation may require decryption then re-encryption

### Operations NOT Requiring Encryption

#### List Objects
- **Endpoints**:
  - `GET /{bucket}?list-type=2` (ListObjectsV2)
  - `GET /{bucket}` (ListObjects)
  - `GET /{bucket}?delimiter=...` (ListObjects with delimiter)
- **Implementation**: Pass-through to backend, no modification needed

#### Head Object
- **Endpoint**: `HEAD /{bucket}/{key}`
- **Implementation**:
  - Fetch metadata from backend
  - If encrypted, modify metadata to show original values
  - Hide encryption-specific metadata

#### Delete Object
- **Endpoints**:
  - `DELETE /{bucket}/{key}`
  - `POST /{bucket}?delete` (DeleteObjects)
- **Implementation**: Pass-through to backend, no decryption needed

#### Bucket Operations
- **Endpoints**: All bucket-level operations (create, delete, policy, etc.)
- **Implementation**: Pass-through to backend, no encryption concerns

## Request/Response Processing Strategy

### Request Parsing
```go
type S3Request struct {
    Method      string
    Bucket      string
    Key         string
    QueryParams map[string]string
    Headers     map[string]string
    Body        io.Reader
    IsEncrypted bool // For GET requests
}
```

### Response Modification
```go
type S3Response struct {
    StatusCode  int
    Headers     map[string]string
    Body        io.Reader
    IsEncrypted bool
}
```

## Authentication and Authorization

### Strategy
- **Default mode**: Gateway uses its own configured backend credentials for all requests
- **Client credentials mode** (`use_client_credentials: true`): Gateway extracts credentials from client requests
  - **Supported**: Query parameter authentication (`?AWSAccessKeyId=...&AWSSecretAccessKey=...`)
  - **Presigned URLs**: Supported for `GET` and `PUT` operations.
    - The gateway validates the Presigned URL signature using the configured backend credentials.
    - This requires the client to sign requests using the *same* credentials that the gateway is configured to use for the backend.
    - **Constraint**: The gateway essentially validates the signature on behalf of the backend, as it cannot forward the signed request directly (host header mismatch invalidates signature).
  - **NOT supported**: AWS Signature V4 (Authorization header) - signature includes Host header which prevents forwarding
- **No additional auth**: Gateway trusts client authentication
- **Future enhancement**: Support for gateway-specific authentication

### Implementation
```go
// Default mode: Use configured backend credentials for S3 client
// Client credentials mode: Extract credentials from request query parameters
// Note: Signature V4 (Authorization header) is not supported in client credentials mode
backendClient := s3.New(session.Must(session.NewSession(&aws.Config{
    Credentials: credentials.NewStaticCredentials(accessKey, secretKey, ""),
})))
```

### Presigned URL Compatibility Caveats
1.  **Host Header Mismatch**: Presigned URLs generated by clients usually sign the `Host` header. When the gateway forwards this request to the real backend, the `Host` header changes, invalidating the signature.
    *   **Solution**: The gateway intercepts the Presigned URL request, validates the signature locally using its configured backend credentials, and then creates a *new* request to the backend using the gateway's backend credentials.
    *   **Requirement**: The client must use the same Access Key and Secret Key as the gateway's backend configuration. If the client uses different credentials, the gateway cannot validate the signature (unless it has access to those credentials, which it currently doesn't).
2.  **Path Style vs Virtual Host Style**: Clients should prefer Path Style addressing when generating presigned URLs for the gateway to avoid DNS resolution issues, though the gateway handles virtual host style if DNS is configured correctly.

## Header and Metadata Handling

### Preserved Headers
- `Content-Type`
- `Content-Length` (modified for encryption overhead)
- `ETag` (modified for encrypted content)
- `Last-Modified`
- `x-amz-meta-*` (user metadata)
- `x-amz-tagging`
- `x-amz-version-id`

### Added Encryption Metadata
- `x-amz-meta-encrypted`: "true"
- `x-amz-meta-encryption-algorithm`: "AES256-GCM" or "ChaCha20-Poly1305"
- `x-amz-meta-encryption-key-salt`: base64-encoded salt
- `x-amz-meta-original-content-length`: original size
- `x-amz-meta-original-etag`: original ETag

### Hidden Headers
- Never expose backend-specific headers
- Filter internal encryption metadata from client responses

## Encryption Metadata Format

### Storage Format
```json
{
  "encrypted": true,
  "algorithm": "AES256-GCM" | "ChaCha20-Poly1305",
  "key_salt": "base64-encoded-salt",
  "original_size": 12345,
  "original_etag": "original-etag-value",
  "iv": "base64-encoded-iv"
}
```

### Metadata Keys
- Use `x-amz-meta-` prefix for S3 compatibility
- Compress metadata if it exceeds header size limits
- Store in separate metadata object for large metadata

## Error Handling and Translation

### Backend Error Translation
```go
// Map backend errors to appropriate S3 errors
switch backendErr.Code {
case "NoSuchBucket":
    return s3error.NoSuchBucket
case "AccessDenied":
    return s3error.AccessDenied
case "InvalidObjectName":
    return s3error.KeyTooLongError
default:
    return s3error.InternalError
}
```

### Encryption Error Handling
- **Decryption failures**: Return 500 Internal Server Error
- **Key derivation errors**: Return 500 Internal Server Error
- **Corrupted data**: Return 500 Internal Server Error with specific message

### Client Error Responses
- **Invalid requests**: 400 Bad Request
- **Authentication failures**: 403 Forbidden
- **Not found**: 404 Not Found
- **Method not allowed**: 405 Method Not Allowed

## Streaming vs Buffered Operations

### Streaming Strategy
- **PUT operations**: Stream encryption to avoid memory pressure
- **GET operations**: Stream decryption for large objects
- **Memory limits**: Configure maximum buffer size
- **Fallback**: Buffer small objects, stream large ones

### Implementation
```go
type StreamProcessor interface {
    Process(reader io.Reader) io.Reader
}

func (e *EncryptionEngine) EncryptStream(reader io.Reader) io.Reader {
    return &encryptReader{source: reader, cipher: e.cipher}
}

func (e *EncryptionEngine) DecryptStream(reader io.Reader) io.Reader {
    return &decryptReader{source: reader, cipher: e.cipher}
}
```

## Multipart Upload Handling

### Strategy
- Encrypt each part individually
- Maintain part boundaries and sizes
- Store encryption metadata per part
- Reassemble with correct encryption order

### Metadata Storage
- Store part encryption metadata in separate object
- Use multipart upload ID as key for metadata
- Clean up metadata on completion/failure

## Edge Cases and Special Handling

### Range Requests
- **GET with Range header**: Optimized for chunked encryption format
- **Implementation**:
  - If object uses chunked encryption: compute encrypted byte range and fetch only needed chunks from backend; decrypt only those chunks, respond with 206 and correct Content-Range
  - If legacy (buffered) encryption or plaintext: forward client range to backend or decrypt fully then apply range
- **Performance impact**: Significantly reduced bandwidth and CPU for chunked format

### Object Versioning
- **Versioned objects**: Encrypt/decrypt specific versions
- **Version metadata**: Store encryption info per version
- **Delete markers**: Handle appropriately

### Object Locking
- **Legal hold**: Pass through to backend
- **Retention**: Pass through to backend
- **Encryption compatibility**: Ensure no conflicts

### Compression
- **Client compression**: Encrypt after compression
- **Backend compression**: Handle if backend compresses
- **Metadata**: Track compression status

## Testing Strategy

### API Compatibility Testing
- **AWS SDK tests**: Use official AWS SDK test suites
- **Third-party tools**: Test with rclone, s3cmd, MinIO client
- **S3 compatibility suites**: Use existing S3 compatibility test frameworks

### Encryption Testing
- **Round-trip tests**: Encrypt → Decrypt → Verify identical
- **Corruption tests**: Test behavior with corrupted encrypted data
- **Key rotation tests**: Test key change scenarios
- **Large file tests**: Test with objects > 5GB

### Performance Testing
- **Throughput**: Measure encryption/decryption speeds
- **Concurrent requests**: Test under load
- **Memory usage**: Monitor memory consumption
- **Latency**: Measure request latency impact

## Implementation Phases

### Phase 1: Basic Operations
- Implement PUT/GET for simple objects
- Basic encryption/decryption
- Single backend provider (AWS)

### Phase 2: Advanced Operations
- Multipart uploads
- Range requests
- Object versioning
- Multiple backend providers

### Phase 3: Production Hardening
- Error handling improvements
- Performance optimizations
- Comprehensive testing
- Monitoring and metrics

### Phase 4: Advanced Features
- Key rotation
- Compression integration
- Custom encryption algorithms
- Advanced S3 features support
