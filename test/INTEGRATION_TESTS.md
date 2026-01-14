# Integration Tests with Cosmian KMS

This document describes how to run integration tests that use a real Cosmian KMS instance.

## Prerequisites

- Docker installed and running
- Go 1.22+ installed
- Network access to pull Docker images

## Running Integration Tests

Integration tests are tagged with `integration` build tag and require Docker to be running.

### Run All Integration Tests

```bash
go test -tags=integration ./test -v
```

### Run Specific Integration Test

```bash
go test -tags=integration ./test -v -run TestCosmianKMSIntegration
go test -tags=integration ./test -v -run TestCosmianKMSKeyRotation
go test -tags=integration ./test -v -run TestCosmianKMSGatewayIntegration
```

### Skip Integration Tests in Regular Test Runs

Integration tests are automatically skipped when running regular tests:

```bash
go test ./test  # Integration tests are skipped
```

## What the Tests Do

### TestCosmianKMSIntegration

Tests basic encryption/decryption operations with Cosmian KMS:

1. Starts a Cosmian KMS Docker container
2. Creates a wrapping key
3. Connects via KMIP protocol
4. Tests:
   - Basic encryption/decryption
   - Large file encryption (1MB+)
   - Multiple objects with same key
   - Chunked encryption mode

### TestCosmianKMSKeyRotation

Tests key rotation with dual-read window support:

1. Creates two wrapping keys (version 1 and 2)
2. Encrypts objects with version 1
3. Rotates to version 2
4. Verifies objects encrypted with version 1 can still be decrypted (dual-read window)

### TestCosmianKMSGatewayIntegration

Tests the full gateway stack with Cosmian KMS:

1. Starts Cosmian KMS container
2. Starts MinIO backend container
3. Starts gateway with KMS configured
4. Tests PUT/GET operations through the gateway
5. Verifies encryption/decryption end-to-end

## Test Environment

The integration tests automatically:

- Start Cosmian KMS container on ports 5696 (KMIP) and 9998 (HTTP API)
- Start MinIO container on ports 9000 (S3) and 9001 (Console)
- Clean up containers after tests complete

## Troubleshooting

### Docker Not Available

If Docker is not available, tests will be skipped automatically.

### Port Conflicts

If ports 5696, 9998, 9000, or 9001 are already in use, tests may fail. Stop conflicting services or modify port mappings in the test code.

### Cosmian KMS Not Ready

If Cosmian KMS doesn't start within 30 seconds, the test will fail. Check Docker logs:

```bash
docker logs <container-name>
```

### Key Creation Issues

The tests attempt to create wrapping keys via HTTP API. If this fails (e.g., due to authentication), the tests will use a fallback test key ID. This is acceptable for testing the KMIP integration flow.

## Manual Testing

To manually test with a running Cosmian KMS:

1. Start Cosmian KMS:
   ```bash
   docker run -d -p 5696:5696 -p 9998:9998 --name cosmian-kms ghcr.io/cosmian/kms:5.14.1 server
   ```

2. Create a wrapping key using Cosmian CLI or HTTP API

3. Configure the gateway with KMS settings

4. Run the gateway and test operations

## Model Attribution

All integration test functions are implemented by **Auto (agent router)** as indicated in function comments.

