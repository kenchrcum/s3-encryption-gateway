# Integration Tests with Cosmian KMS

> **Superseded** — this document is outdated. The authoritative testing guide
> is **[docs/TESTING.md](../docs/TESTING.md)**.

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
   docker run -d -p 5696:5696 -p 9998:9998 --name cosmian-kms --entrypoint cosmian_kms ghcr.io/cosmian/kms:5.14.1
   ```

2. Create a wrapping key using Cosmian CLI or HTTP API

3. Configure the gateway with KMS settings

4. Run the gateway and test operations

---

## UploadPartCopy (MinIO) Integration Tests

Added by V0.6-S3-3. Covers the 10 named tests from the issue list plus 3
Phase-E encrypted-MPU tests.

### Prerequisites

- **Docker Compose** (running MinIO via `test/docker-compose.yml`):
  ```bash
  cd test && docker-compose up -d
  ```
- `mc` CLI **only for** `TestUploadPartCopy_CrossBucket_ReadDenied_Integration`
  (test 9); that test skips cleanly if `mc` is absent

**Important:** Tests require the docker-compose services to be running. They will skip/fail if MinIO cannot be reached at `http://127.0.0.1:9000`.

### Run

```bash
# First, ensure docker-compose services are running
cd test && docker-compose up -d

# Then run the tests
go test -tags=integration -race -v -run 'TestUploadPartCopy_' ./test
```

### Tests

| # | Name | What it checks |
|---|------|----------------|
| 1 | `TestUploadPartCopy_Chunked` | Chunked-encrypted source → plaintext dst, byte-for-byte round trip |
| 2 | `TestUploadPartCopy_Chunked_WithRange` | Mid-chunk, boundary, cross-chunk range copies |
| 3 | `TestUploadPartCopy_Legacy` | Legacy-AEAD source; `gateway_upload_part_copy_legacy_fallback_total` increments |
| 4 | `TestUploadPartCopy_Plaintext` | Backend-native fast path, no decrypt activity |
| 5 | `TestUploadPartCopy_LargeSource_MustUseRange` | HeadObject override reports > 5 GiB; no-range → 400, ranged → 200 |
| 6 | `TestUploadPartCopy_CrossBucket` | Two buckets, two per-bucket passwords, round trip |
| 7 | `TestUploadPartCopy_AbortMidway` | Abort after 2 parts; no orphan objects |
| 8 | `TestUploadPartCopy_MixedWithUploadPart` | Interleaved UploadPart + UploadPartCopy, 4-part verify |
| 9 | `TestUploadPartCopy_CrossBucket_ReadDenied_Integration` | alice creds (write-only on dst) → 403; requires `mc` |
| 10 | `TestUploadPartCopy_PlaintextSource_EncryptedDestBucket_Refused_Integration` | `require_encryption: true` on dst → 500 |

---

## Encrypted Multipart Upload (MinIO + Valkey) Integration Tests

Added by V0.6-S3-3. Covers Phase-E (UploadPartCopy → encrypted MPU dst) and
end-to-end encrypted MPU with PasswordKeyManager.

### Prerequisites

- **Docker Compose** (running MinIO + Valkey via `test/docker-compose.yml`):
  ```bash
  cd test && docker-compose up -d
  ```

**Important:** Tests require BOTH MinIO and Valkey to be running. They will skip if either service is unavailable.

### Run

```bash
# First, ensure docker-compose services are running
cd test && docker-compose up -d

# Then run the tests
go test -tags=integration -race -v -run 'TestEncryptedMPU_|TestUploadPartCopy_MPU_' ./test
```

### Tests

| # | Name | What it checks |
|---|------|----------------|
| 11 | `TestUploadPartCopy_MPU_PlaintextSource_EncryptedDest` | Plaintext → encrypted MPU; at-rest ciphertext ≠ plaintext |
| 12 | `TestUploadPartCopy_MPU_ChunkedSource_EncryptedDest_WithRange` | Chunked range → encrypted MPU; downloaded slice matches |
| 13 | `TestUploadPartCopy_MPU_LegacySource_EncryptedDest` | Legacy → encrypted MPU + legacy fallback metric increments |
| 14 | `TestEncryptedMPU_PasswordKeyManager_SmallObject` | 16 MiB / 2 parts, byte-for-byte round trip |
| 15 | `TestEncryptedMPU_PasswordKeyManager_Ranged_GET` | 64 MiB / 8 parts; mid-chunk, cross-chunk, cross-part GET ranges |
| 16 | `TestEncryptedMPU_PasswordKeyManager_AtRestCiphertext` | Raw backend bytes ≠ plaintext; manifest companion exists |
| 17 | `TestEncryptedMPU_PasswordKeyManager_AbortDeletesState` | Abort clears Valkey state; ListParts + GetObject fail |
| 18 | `TestCosmianKMS_EncryptedMPU_RoundTrip` | Cosmian-wrapped DEK, 16 MiB / 2 parts, round trip |

### Troubleshooting

- **MinIO connection refused at http://127.0.0.1:9000**: 
  ```bash
  cd test && docker-compose up -d minio
  docker-compose ps  # Verify minio-test is healthy
  ```

- **Valkey connection refused**: 
  ```bash
  cd test && docker-compose up -d valkey
  docker-compose ps  # Verify valkey-test is healthy
  ```

- **Tests skip instead of failing**: This is expected behavior. Tests will skip if docker-compose services are not available.

- **mc not found** (test 9 skips cleanly): This is expected. Test 9 requires `mc` CLI for multi-credential testing. Install via `https://min.io/docs/minio/linux/reference/minio-mc.html` if needed.

- **Cosmian test** (test 18): Cosmian KMS container is started automatically by the test. If test is skipped, Docker is not available.

