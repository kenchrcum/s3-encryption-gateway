# S3 Encryption Gateway - Architecture Design

## Overview

The S3 Encryption Gateway is a transparent proxy that sits between S3 clients and S3-compatible storage providers. It provides client-side encryption/decryption of objects while maintaining full S3 API compatibility.

## Language Choice: Go

After analyzing multiple languages, Go was selected for this project due to:

- **Excellent HTTP performance**: Go's HTTP server and client implementations are highly optimized
- **Superior concurrency**: Goroutines provide efficient concurrent request handling
- **Built-in crypto support**: Standard library includes AES, HMAC, and other essential crypto primitives
- **Container-friendly**: Small binaries, fast startup times, minimal resource usage
- **Mature ecosystem**: Excellent AWS SDK for Go, HTTP libraries, and middleware support

## High-Level Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   S3 Client     │────│  Encryption      │────│  S3 Backend     │
│   (awscli, SDK) │    │  Gateway         │    │  (AWS, Wasabi,  │
│                 │    │                  │    │   Hetzner, etc.) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │   Encryption     │
                       │   Key Store      │
                       └──────────────────┘
```

## Core Components

### 1. HTTP Server (Gateway)
- **Purpose**: Receives S3 API requests from clients
- **Technology**: Go's net/http with custom middleware
- **Responsibilities**:
  - Parse and validate S3 API requests
  - Route requests to appropriate handlers
  - Handle authentication and authorization
  - Provide health check endpoints

### 2. Request Processor
- **Purpose**: Processes S3 requests and applies encryption logic
- **Components**:
  - **S3RequestParser**: Parses S3 API requests into structured data
  - **EncryptionEngine**: Handles encrypt/decrypt operations
  - **S3Client**: Forwards requests to backend S3 provider

### 3. Encryption Engine
- **Purpose**: Provides client-side encryption/decryption
- **Features**:
  - AES-256-GCM (default) and ChaCha20-Poly1305 authenticated encryption
  - Configurable key derivation from password
  - Optional compression before encryption (configurable)
  - Support for future encryption algorithms
  - Metadata preservation (content-type, etags, etc.)

### 4. Backend S3 Client
- **Purpose**: Communicates with actual S3-compatible storage
- **Features**:
  - Pluggable provider support (AWS, Wasabi, Hetzner, MinIO)
  - Automatic retry logic
  - Connection pooling
  - Region/bucket configuration

### 5. Configuration Manager
- **Purpose**: Manages application configuration
- **Sources**:
  - Environment variables
  - Configuration files
  - Kubernetes secrets/configmaps
- **Configuration Items**:
  - Encryption password/key
  - Backend S3 endpoint and credentials
  - Listen port and bind address
  - TLS certificates (optional)

## Data Flow

### Object Upload (PUT)
```
1. Client → Gateway: PUT /bucket/key
2. Gateway → RequestParser: Parse request
3. RequestParser → EncryptionEngine: Encrypt object data
4. EncryptionEngine → BackendClient: PUT encrypted data
5. BackendClient → Gateway: Response
6. Gateway → Client: Response (with modified metadata)
```

### Object Download (GET)
```
1. Client → Gateway: GET /bucket/key
2. Gateway → RequestParser: Parse request
3. RequestParser → BackendClient: GET encrypted data
4. BackendClient → EncryptionEngine: Decrypt object data
5. EncryptionEngine → Gateway: Decrypted response
6. Gateway → Client: Response (original data)
```

### List Objects (GET with query params)
```
1. Client → Gateway: GET /bucket/?list-type=2
2. Gateway → BackendClient: Forward request (no encryption needed)
3. BackendClient → Gateway: Response
4. Gateway → Client: Response (unchanged)
```

## Key Design Decisions

### Encryption Strategy
- **Client-side only**: Never trust server-side encryption
- **Authenticated encryption**: Use AES-256-GCM (default) or ChaCha20-Poly1305 for confidentiality and integrity
- **Key derivation**: PBKDF2 from user-provided password
- **Metadata handling**: Preserve original metadata, add encryption markers

### API Compatibility
- **Transparent proxy**: Clients see standard S3 API
- **Header preservation**: Maintain all S3 headers and metadata
- **Error translation**: Convert backend errors to appropriate S3 error responses
- **Version support**: Focus on S3 API v2 (most widely supported)

### Concurrency Model
- **Goroutines**: One goroutine per request
- **Non-blocking I/O**: All network operations are async
- **Resource limits**: Configurable connection pools and timeouts
- **Graceful shutdown**: Proper cleanup on termination signals

## Interfaces and Abstractions

### EncryptionEngine Interface
```go
type EncryptionEngine interface {
    Encrypt(reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error)
    Decrypt(reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error)
    IsEncrypted(metadata map[string]string) bool
}
```

### S3Backend Interface
```go
type S3Backend interface {
    PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string) error
    GetObject(ctx context.Context, bucket, key string) (io.Reader, map[string]string, error)
    DeleteObject(ctx context.Context, bucket, key string) error
    ListObjects(ctx context.Context, bucket, prefix string, opts ListOptions) ([]ObjectInfo, error)
    HeadObject(ctx context.Context, bucket, key string) (map[string]string, error)
}
```

### Configuration Interface
```go
type Config struct {
    ListenAddr      string
    EncryptionKey   string
    Backend         BackendConfig
    Compression     CompressionConfig
    TLS             TLSConfig
    Logging         LoggingConfig
}

type BackendConfig struct {
    Endpoint        string
    Region          string
    AccessKey       string
    SecretKey       string
    Bucket          string
    Provider        string // aws, wasabi, hetzner, minio
}

type CompressionConfig struct {
    Enabled         bool
    MinSize         int64
    ContentTypes    []string
    Algorithm       string
    Level           int
}
```

## Error Handling

### Error Types
- **Client Errors**: Invalid requests (400 Bad Request)
- **Authentication Errors**: Invalid credentials (403 Forbidden)
- **Backend Errors**: Translate S3 provider errors appropriately
- **Encryption Errors**: Key issues, corruption (500 Internal Server Error)
- **Network Errors**: Timeouts, connection failures (502 Bad Gateway)

### Error Propagation
- Preserve original error codes where possible
- Add context for debugging
- Structured logging with error details
- Metrics collection for monitoring

## Security Considerations

### Key Management
- Password-based key derivation (PBKDF2)
- No key storage on disk
- Runtime key derivation with salt
- Future: Support for key management services

### Data Protection
- TLS termination optional (Kubernetes handles TLS)
- Secure memory handling for keys
- No temporary file storage of decrypted data
- Streaming encryption/decryption

### Audit and Monitoring
- Request logging with sensitive data redaction
- Metrics for performance monitoring
- Health checks for container orchestration
- Structured logging in JSON format

## Deployment Architecture

### Container Design
- **Base Image**: Alpine Linux with Go binary
- **Multi-stage build**: Separate build and runtime stages
- **Security**: Non-root user, minimal attack surface
- **Configuration**: Environment variables and mounted config files

### Kubernetes Integration
- **Deployment**: Rolling updates, resource limits
- **Service**: Load balancing across pods
- **ConfigMap/Secret**: Configuration and credentials
- **Ingress**: External access with TLS termination
- **Health Checks**: Readiness and liveness probes

## Development Roadmap

### Phase 1: Core Proxy
- Basic HTTP server
- S3 request parsing
- Backend S3 client
- Docker containerization

### Phase 2: Encryption
- AES-256-GCM implementation
- Key derivation from password
- Encrypt/decrypt pipeline
- Metadata handling

### Phase 3: Production Features
- TLS support
- Metrics and monitoring
- Multiple backend providers
- Comprehensive testing

### Phase 4: Production Readiness ✅
- TLS/HTTPS support
- Comprehensive monitoring and metrics
- Security hardening (security headers, rate limiting)
- Performance benchmarks
- Load testing utilities
- Production Kubernetes manifests (ServiceMonitor, HPA, NetworkPolicy)
- Security audit recommendations

**Status**: Complete. All production features implemented.
