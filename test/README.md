# Integration Testing

This directory contains integration tests that run against a real MinIO S3-compatible backend.

## Requirements

To run integration tests, you need one of:

1. **Docker** (recommended) - Tests will automatically use Docker to start MinIO
2. **Docker Compose** - For easier management of test MinIO instance
3. **MinIO binary** - Installed in PATH as fallback

## Running Integration Tests

### With Docker Compose (recommended)

```bash
# Start MinIO in background
docker-compose -f test/docker-compose.yml up -d

# Run integration tests
go test -v ./test/... -run TestS3Gateway

# Stop MinIO
docker-compose -f test/docker-compose.yml down
```

### With Docker directly

```bash
# Tests will automatically start MinIO using Docker
go test -v ./test/... -run TestS3Gateway
```

### Skip integration tests

```bash
# Use -short flag to skip integration tests
go test -short ./...
```

## Testing against External Providers

You can run integration tests against real S3 providers (AWS, Wasabi, Hetzner, Backblaze B2) by setting environment variables.

### AWS S3
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_BUCKET_NAME=your_test_bucket
export AWS_REGION=us-east-1
# Optional: export AWS_ENDPOINT=...

go test -v ./test/provider_test.go -run TestProvider_CoreFlows
```

### Wasabi
```bash
export WASABI_ACCESS_KEY_ID=your_access_key
export WASABI_SECRET_ACCESS_KEY=your_secret_key
export WASABI_BUCKET_NAME=your_test_bucket
export WASABI_REGION=us-east-1
# Optional: export WASABI_ENDPOINT=https://s3.wasabisys.com

go test -v ./test/provider_test.go -run TestProvider_CoreFlows
```

### Hetzner Storage Box
```bash
export HETZNER_ACCESS_KEY_ID=your_access_key
export HETZNER_SECRET_ACCESS_KEY=your_secret_key
export HETZNER_BUCKET_NAME=your_test_bucket
# Optional: export HETZNER_ENDPOINT=https://fs.hetzner.de

go test -v ./test/provider_test.go -run TestProvider_CoreFlows
```

### Backblaze B2
See [BACKBLAZE_B2_TESTING.md](BACKBLAZE_B2_TESTING.md) for detailed instructions.

## Test Coverage

Integration tests cover:

- ✅ Basic PUT/GET operations with encryption/decryption
- ✅ Multipart upload with encryption
- ✅ Range requests
- ✅ Object copy operations
- ✅ Batch delete operations
- ✅ List objects
- ✅ Error handling with proper S3 error responses

## MinIO Configuration

The test MinIO server uses:
- **Endpoint**: `http://localhost:9000`
- **Access Key**: `minioadmin`
- **Secret Key**: `minioadmin`
- **Bucket**: `test-bucket` (created automatically)

## Troubleshooting

### MinIO fails to start

- Ensure Docker is running: `docker ps`
- Check if port 9000 is already in use
- Try stopping existing containers: `docker-compose -f test/docker-compose.yml down`

### Tests timeout

- Increase timeout in test files if your system is slow
- Check MinIO health: `curl http://localhost:9000/minio/health/live`

### Permission errors

- Ensure Docker daemon is accessible
- On Linux, you may need `sudo` for Docker commands
- Consider adding your user to the `docker` group
