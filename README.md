# S3 Encryption Gateway

A transparent HTTP proxy that provides client-side encryption for S3-compatible storage services. The gateway sits between S3 clients and backend storage providers, encrypting/decrypting data transparently while maintaining full S3 API compatibility.

## Features

- **Transparent Encryption**: Automatically encrypts/decrypts S3 objects using AES-256-GCM
- **S3 API Compatible**: Full compatibility with Amazon S3 API and S3-compatible services
- **Multi-Provider Support**: Works with AWS S3, MinIO, Wasabi, Hetzner, and other S3-compatible providers
- **Client-Side Encryption**: Data is encrypted before being sent to backend storage
- **Production Ready**: Health checks, metrics, logging, and Kubernetes deployment support

## Architecture

```
???????????????    ????????????????????    ???????????????
? S3 Client   ?????? Encryption       ?????? S3 Backend  ?
? (awscli)    ?    ? Gateway          ?    ? (AWS, etc.) ?
???????????????    ????????????????????    ???????????????
```

## Quick Start

### Prerequisites

- Go 1.22 or later
- Docker (optional, for containerized deployment)
- Kubernetes (optional, for K8s deployment)

### Building

```bash
# Build the binary
make build

# Or build directly
go build -o bin/s3-encryption-gateway ./cmd/server
```

### Configuration

Create a `config.yaml` file (see `config.yaml.example` for reference):

```yaml
listen_addr: ":8080"
log_level: "info"

backend:
  endpoint: "https://s3.amazonaws.com"
  region: "us-east-1"
  access_key: "YOUR_ACCESS_KEY"
  secret_key: "YOUR_SECRET_KEY"
  provider: "aws"

encryption:
  password: "YOUR_ENCRYPTION_PASSWORD"
```

Or use environment variables:

```bash
export LISTEN_ADDR=":8080"
export BACKEND_ENDPOINT="https://s3.amazonaws.com"
export BACKEND_REGION="us-east-1"
export BACKEND_ACCESS_KEY="your-access-key"
export BACKEND_SECRET_KEY="your-secret-key"
export ENCRYPTION_PASSWORD="your-encryption-password"
```

### Running

```bash
# Run locally
make run

# Or run directly
./bin/s3-encryption-gateway
```

### Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# View coverage report
open coverage.html
```

## Development

### Project Structure

```
s3-encryption-gateway/
??? cmd/server/          # Main application entrypoint
??? internal/
?   ??? api/            # HTTP handlers and routing
?   ??? config/         # Configuration management
?   ??? crypto/         # Encryption/decryption logic (Phase 2)
?   ??? s3/             # S3 client implementations
?   ??? middleware/      # HTTP middleware
?   ??? metrics/        # Monitoring and metrics
??? k8s/                # Kubernetes manifests
??? docker/              # Docker-related files
??? test/                # Test utilities
```

### Development Tools

Install development tools:

```bash
make install-tools
```

Format code:

```bash
make fmt
```

Run linter:

```bash
make lint
```

Security scan:

```bash
make security-scan
```

## Docker Deployment

### Build Docker Image

```bash
make docker-build
```

### Run Docker Container

```bash
docker run -p 8080:8080 \
  -e BACKEND_ENDPOINT="https://s3.amazonaws.com" \
  -e BACKEND_REGION="us-east-1" \
  -e BACKEND_ACCESS_KEY="your-key" \
  -e BACKEND_SECRET_KEY="your-secret" \
  -e ENCRYPTION_PASSWORD="your-password" \
  s3-encryption-gateway:latest
```

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster
- kubectl configured

### Deploy

1. Create secrets (use `k8s/secrets.yaml.example` as template):

```bash
kubectl create secret generic s3-encryption-gateway-secrets \
  --from-literal=backend-access-key=YOUR_KEY \
  --from-literal=backend-secret-key=YOUR_SECRET \
  --from-literal=encryption-password=YOUR_PASSWORD
```

2. Apply ConfigMap:

```bash
kubectl apply -f k8s/configmap.yaml
```

3. Apply Deployment:

```bash
kubectl apply -f k8s/deployment.yaml
```

### Health Checks

The gateway provides health check endpoints:

- `/health` - General health status
- `/ready` - Readiness probe (for Kubernetes)
- `/live` - Liveness probe (for Kubernetes)
- `/metrics` - Prometheus metrics

## API Usage

### Upload Object (PUT)

```bash
curl -X PUT http://localhost:8080/my-bucket/my-key \
  -H "Content-Type: text/plain" \
  --data "Hello, World!"
```

### Download Object (GET)

```bash
curl http://localhost:8080/my-bucket/my-key
```

### Delete Object (DELETE)

```bash
curl -X DELETE http://localhost:8080/my-bucket/my-key
```

### List Objects (GET)

```bash
curl "http://localhost:8080/my-bucket?prefix=test"
```

## Implementation Status

### Phase 1: Core Infrastructure ?
- [x] Project structure and Go modules
- [x] HTTP server with routing
- [x] S3 backend client
- [x] Configuration management
- [x] Health checks and middleware
- [x] Logging and error handling
- [x] Docker and Kubernetes deployment
- [x] Unit tests

### Phase 2: Encryption Implementation (In Progress)
- [ ] AES-256-GCM encryption engine
- [ ] PBKDF2 key derivation
- [ ] Streaming encrypt/decrypt
- [ ] Metadata handling

### Phase 3: S3 API Compatibility (Planned)
- [ ] Full S3 operation support
- [ ] Multipart uploads
- [ ] Range requests
- [ ] Error translation

### Phase 4: Production Features (Planned)
- [ ] TLS support
- [ ] Advanced monitoring
- [ ] Performance optimization
- [ ] Security hardening

## Security Considerations

- **Encryption Password**: Store encryption passwords securely (use secrets management)
- **Backend Credentials**: Use IAM roles or secure credential storage
- **Network**: Deploy behind TLS termination (e.g., Kubernetes Ingress)
- **Access Control**: Restrict gateway access to authorized clients

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linter
5. Submit a pull request

See `DEVELOPMENT_GUIDE.md` for detailed development guidelines.

## License

[Specify License]

## Support

[Add support information]