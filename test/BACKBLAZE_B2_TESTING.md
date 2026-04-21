# Backblaze B2 Integration Testing

> **Superseded** — this document is outdated. B2 tests are now provider-parameterised
> in the conformance suite (`test/conformance/`). See **[docs/TESTING.md](../docs/TESTING.md)**
> for the plug-in recipe and run instructions.

This document describes how to run integration tests against Backblaze B2 (S3-compatible storage).

## Overview

The Backblaze B2 integration tests verify that the S3 Encryption Gateway works correctly with Backblaze B2's S3-compatible API. These tests are particularly useful for:

- Verifying S3 compatibility across different providers
- Testing metadata handling (critical for KMS integration)
- Validating that encryption/decryption works with real cloud storage
- Identifying provider-specific issues

## Prerequisites

1. **Backblaze B2 Account**: You need a Backblaze B2 account with:
   - An application key with read/write permissions
   - A bucket created in the EU Central region (or adjust the endpoint in the test)

2. **Environment Variables**: The following environment variables must be set:

   ```bash
   export B2_ACCESS_KEY_ID="your-application-key-id"
   export B2_SECRET_ACCESS_KEY="your-application-key"
   export B2_BUCKET_NAME="your-bucket-name"
   ```

3. **Docker** (optional): Required only for KMS integration tests (`TestBackblazeB2_WithCosmianKMS`)

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `B2_ACCESS_KEY_ID` | Your Backblaze B2 application key ID | `001234567890abcdef1234567890abcdef00000001` |
| `B2_SECRET_ACCESS_KEY` | Your Backblaze B2 application key (secret) | `K001234567890abcdef1234567890abcdef` |
| `B2_BUCKET_NAME` | Name of your B2 bucket | `my-test-bucket` |

### Getting Your Credentials

1. Log in to your [Backblaze B2 account](https://secure.backblaze.com/user_signin.htm)
2. Navigate to **App Keys** in the left sidebar
3. Click **Add a New Application Key**
4. Configure the key:
   - **Name**: Give it a descriptive name (e.g., "S3 Gateway Testing")
   - **Allow List All Bucket Names**: Check this if you want to test with multiple buckets
   - **Allow Read Files**: Check this
   - **Allow Write Files**: Check this
   - **Allow Delete Files**: Check this (for cleanup)
   - **Allow List Files**: Check this
   - **File name prefix**: Leave empty (or specify a prefix for safety)
   - **Duration**: Choose "Never expire" or set an expiration date
5. Click **Create New Key**
6. Copy the **keyID** and **applicationKey** values

### Setting Environment Variables

**Linux/macOS:**
```bash
export B2_ACCESS_KEY_ID="your-key-id"
export B2_SECRET_ACCESS_KEY="your-application-key"
export B2_BUCKET_NAME="your-bucket-name"
```

**Windows (PowerShell):**
```powershell
$env:B2_ACCESS_KEY_ID="your-key-id"
$env:B2_SECRET_ACCESS_KEY="your-application-key"
$env:B2_BUCKET_NAME="your-bucket-name"
```

**Windows (CMD):**
```cmd
set B2_ACCESS_KEY_ID=your-key-id
set B2_SECRET_ACCESS_KEY=your-application-key
set B2_BUCKET_NAME=your-bucket-name
```

## Running the Tests

### Run All Backblaze B2 Tests

```bash
go test -v -tags=integration -run TestBackblazeB2 ./test
```

### Run Specific Tests

**Basic encryption test:**
```bash
go test -v -tags=integration -run TestBackblazeB2_BasicEncryption ./test
```

**Large file test:**
```bash
go test -v -tags=integration -run TestBackblazeB2_LargeFile ./test
```

**KMS integration test (requires Docker):**
```bash
go test -v -tags=integration -run TestBackblazeB2_WithCosmianKMS ./test
```

**Metadata handling test:**
```bash
go test -v -tags=integration -run TestBackblazeB2_MetadataHandling ./test
```

**Concurrent operations test:**
```bash
go test -v -tags=integration -run TestBackblazeB2_ConcurrentOperations ./test
```

**Multipart upload test:**
```bash
go test -v -tags=integration -run TestBackblazeB2_MultipartUpload ./test
```

**Range request test:**
```bash
go test -v -tags=integration -run TestBackblazeB2_RangeRequest ./test
```

**Batch delete test:**
```bash
go test -v -tags=integration -run TestBackblazeB2_BatchDelete ./test
```

**List objects test:**
```bash
go test -v -tags=integration -run TestBackblazeB2_ListObjects ./test
```

**Extended KMS integration test:**
```bash
go test -v -tags=integration -run TestBackblazeB2_WithCosmianKMS_Extended ./test
```

**Load test:**
```bash
go test -v -tags=integration -run TestBackblazeB2_LoadTest ./test
```

**Final cleanup test (runs last):**
```bash
go test -v -tags=integration -run TestBackblazeB2_ZZZ_FinalCleanup ./test
```

## Test Descriptions

### TestBackblazeB2_BasicEncryption
Tests basic encryption/decryption flow with a small file. Verifies:
- PUT operation with encryption
- GET operation with decryption
- Data integrity after round-trip

### TestBackblazeB2_LargeFile
Tests encryption/decryption with a larger file (100KB). Verifies:
- Handling of larger payloads
- Streaming encryption/decryption
- Performance with larger files

### TestBackblazeB2_WithCosmianKMS
Tests full integration with Cosmian KMS. Verifies:
- KMS key wrapping/unwrapping
- Metadata storage and retrieval (critical for KMS)
- End-to-end encryption with external KMS

### TestBackblazeB2_MetadataHandling
Tests metadata consistency across multiple operations. Verifies:
- Metadata is correctly stored
- Metadata is correctly retrieved
- No corruption during S3 round-trip

### TestBackblazeB2_ConcurrentOperations
Tests concurrent PUT/GET operations. Verifies:
- Thread safety
- No race conditions
- Correct behavior under load

### TestBackblazeB2_MultipartUpload
Tests multipart upload functionality with large files (5MB). Verifies:
- Large file handling
- Multipart upload process
- Data integrity with large objects

### TestBackblazeB2_RangeRequest
Tests HTTP range request functionality. Verifies:
- Partial content retrieval
- Range header handling
- Data integrity with range requests

### TestBackblazeB2_BatchDelete
Tests batch delete operation. Verifies:
- Multiple object deletion in single request
- XML batch delete format
- Verification of deleted objects

### TestBackblazeB2_ListObjects
Tests list objects operation. Verifies:
- Object listing with prefix
- XML response parsing
- Correct object enumeration

### TestBackblazeB2_WithCosmianKMS_Extended
Extended KMS integration test with multiple objects. Verifies:
- KMS integration with multiple objects
- Comprehensive cleanup with KMS
- End-to-end encryption with external KMS

### TestBackblazeB2_LoadTest
Load test with concurrent workers. Verifies:
- Performance under load
- Concurrent request handling
- Throughput and failure rate metrics

### TestBackblazeB2_ZZZ_FinalCleanup
Final cleanup test that runs last. Verifies:
- All test objects are deleted
- No orphaned objects remain
- Bucket is clean after test run

## Endpoint Configuration

The tests use the EU Central endpoint by default:
- Endpoint: `s3.eu-central-003.backblazeb2.com`
- Region: EU Central

If you need to use a different region, modify the `b2Endpoint` constant in `test/backblaze_b2_integration_test.go`:

```go
const (
    b2Endpoint = "s3.us-west-004.backblazeb2.com"  // Change to your region
)
```

Available regions:
- `s3.us-west-000.backblazeb2.com` (US West)
- `s3.us-west-001.backblazeb2.com` (US West)
- `s3.us-west-002.backblazeb2.com` (US West)
- `s3.us-west-003.backblazeb2.com` (US West)
- `s3.us-west-004.backblazeb2.com` (US West)
- `s3.eu-central-003.backblazeb2.com` (EU Central)
- `s3.ap-southeast-002.backblazeb2.com` (AP Southeast)

## Troubleshooting

### Test Skipped: Missing Environment Variables
If tests are skipped with "Skipping Backblaze B2 test", verify that all three environment variables are set:
```bash
echo $B2_ACCESS_KEY_ID
echo $B2_SECRET_ACCESS_KEY
echo $B2_BUCKET_NAME
```

### Authentication Errors
- Verify your application key has the correct permissions
- Check that the key hasn't expired
- Ensure you're using the correct key ID and application key (not the master key)

### Bucket Not Found
- Verify the bucket name is correct
- Ensure the bucket exists in the region matching your endpoint
- Check that your application key has access to the bucket

### Network Errors
- Verify your network connection
- Check if there are firewall rules blocking access
- Ensure the endpoint URL is correct for your region

### Metadata Issues
If you see "cipher: message authentication failed" errors:
- This indicates metadata corruption during S3 round-trip
- Check the test logs for wrapped key information
- Verify that B2 is correctly handling S3 metadata headers

## Security Notes

⚠️ **Important Security Considerations:**

1. **Never commit credentials**: These environment variables contain sensitive credentials. Never commit them to version control.

2. **Use test buckets**: Create a dedicated bucket for testing to avoid affecting production data.

3. **Limit permissions**: Create application keys with only the minimum required permissions.

4. **Set expiration**: Consider setting an expiration date on test application keys.

5. **Clean up**: The tests attempt to clean up created objects, but verify manually if needed.

## Cleanup and Object Management

The tests use a comprehensive cleanup system that:
- **Tracks all objects** created during each test run
- **Automatically deletes** tracked objects after tests complete
- **Final cleanup test** (`TestBackblazeB2_ZZZ_FinalCleanup`) runs last to ensure no objects remain

### Cleanup Configuration

Cleanup is **enabled by default** for Backblaze B2 (deletion is free). The cleanup system:
- Uses unique test prefixes to isolate test objects
- Tracks objects per test for individual cleanup
- Provides a final cleanup that lists and deletes all test objects

### Provider-Specific Cleanup

The cleanup system is provider-aware:
- **Backblaze B2**: Cleanup enabled (free deletion)
- **Wasabi**: Cleanup disabled (timed deletion costs apply)
- **MinIO**: Cleanup enabled (local, no cost)
- **AWS**: Cleanup enabled (free deletion)

To disable cleanup for a provider, modify `ProviderCleanupConfigs` in `test/cleanup_helper.go`.

## Cost Considerations

Backblaze B2 charges for:
- Storage: $0.005/GB/month
- Downloads: $0.01/GB (first 1GB/day free)
- Uploads: Free

The integration tests create and delete small objects, so costs should be minimal. The cleanup system ensures:
- Objects are automatically deleted after tests
- No orphaned objects remain in the bucket
- Final cleanup test verifies bucket is clean

However, be aware of:
- Storage costs if tests fail before cleanup runs
- Download costs if running tests frequently with large files
- Network costs for data transfer

## See Also

- [Backblaze B2 Documentation](https://www.backblaze.com/b2/docs/)
- [Backblaze B2 S3 Compatible API](https://www.backblaze.com/b2/docs/s3_compatible_api.html)
- [Backblaze B2 Application Keys](https://www.backblaze.com/b2/docs/application_keys.html)

