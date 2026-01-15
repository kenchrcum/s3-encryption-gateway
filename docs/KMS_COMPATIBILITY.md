# KMS Compatibility Guide

This document explains how to create a Key Management Service (KMS) compatible with the S3 Encryption Gateway, or how to integrate with existing KMS solutions.

## Overview

The S3 Encryption Gateway supports two key management modes:

1. **Single Password Mode** (default): Uses a single password for all encryption operations
   - Simple and backward compatible
   - No key rotation support
   - Suitable for small deployments

2. **Key Manager (KMS) Mode**: Uses a KeyManager interface for advanced key management
   - Supports key rotation
   - Multiple key versions for backward compatibility
   - Suitable for enterprise deployments

## Implementation Status

### Currently Supported (v0.5)

- ✅ **Cosmian KMIP**: Fully implemented and tested
  - **JSON/HTTP protocol**: Fully tested and verified in CI
    - Endpoint format: `http://host:9998/kmip/2_1` or `https://host:9998/kmip/2_1`
    - No TLS client certificates required for HTTP
    - TLS `ca_cert` recommended for HTTPS
  - **Binary KMIP protocol**: Implemented but not fully tested in CI
    - Endpoint format: `host:5696`
    - Requires proper TLS configuration (`ca_cert`, `client_cert`, `client_key`) for mutual TLS
    - Use with caution until fully tested
  - Dual-read window for key rotation
  - Health checks integrated into readiness endpoint
  - Integration tests with Docker-based Cosmian KMS server (JSON/HTTP only)

### Planned for v1.0

- 🔜 **AWS KMS**: Planned for v1.0 (see [V1.0-KMS-2](../issues/v1.0-issues.md#v10-kms-2-aws-kms-adapter))
  - Deferred from v0.5 due to cloud provider access requirements for testing
  - Will use AWS SDK v2
  - Support for key aliases, ARNs, and key versioning

- 🔜 **HashiCorp Vault Transit**: Planned for v1.0 (see [V1.0-KMS-3](../issues/v1.0-issues.md#v10-kms-3-hashicorp-vault-transit-adapter))
  - Deferred from v0.5 due to Enterprise license requirements for Transit engine
  - Will support multiple authentication methods
  - Support for key versioning via Vault's key rotation

**Note**: The examples below for AWS KMS and Vault Transit are **conceptual only** and demonstrate the interface pattern. They are not currently implemented and should not be used in production.

## Key Manager Interface

The gateway uses the `KeyManager` interface from `internal/crypto/keymanager.go`:

```go
type KeyManager interface {
    Provider() string
    WrapKey(ctx context.Context, plaintext []byte, metadata map[string]string) (*KeyEnvelope, error)
    UnwrapKey(ctx context.Context, envelope *KeyEnvelope, metadata map[string]string) ([]byte, error)
    ActiveKeyVersion(ctx context.Context) (int, error)
    Close(ctx context.Context) error
}
```

> **Current Support (v0.5):** Only **Cosmian KMIP** is currently implemented and tested. The `KeyManager` interface is designed to support multiple backends, but AWS KMS and Vault Transit adapters are planned for v1.0. See the [Implementation Status](#implementation-status) section below for details.

The envelope returned by `WrapKey` is persisted alongside object metadata:

* `x-amz-meta-encryption-wrapped-key` – DEK ciphertext (base64)
* `x-amz-meta-encryption-kms-id` – wrapping key identifier/ARN
* `x-amz-meta-encryption-kms-provider` – provider hint (e.g. `cosmian-kmip`)
* `x-amz-meta-encryption-key-version` – human-friendly version counter

At decrypt time the engine builds the same envelope and calls `UnwrapKey`. This allows dual-read windows and phased rotations—the key manager implementation decides how many historical keys to keep and how to interpret the metadata.

## Dual-Read Window and Key Rotation

The gateway supports **dual-read windows** for seamless key rotation. This allows objects encrypted with older key versions to be decrypted even after rotation, without requiring immediate re-encryption.

### How Dual-Read Works

When decrypting an object, the gateway:

1. **Reads the key version** from object metadata (`x-amz-meta-encryption-key-version`)
2. **Attempts decryption** with the key version specified in metadata
3. **Falls back to previous versions** if the primary key fails (up to `dual_read_window` versions)
4. **Tracks rotated reads** via metrics and audit logs

### Configuration

Configure the dual-read window in your gateway configuration:

```yaml
encryption:
  key_manager:
    enabled: true
    provider: "cosmian"
    dual_read_window: 2  # Allow reading with previous 2 key versions
    rotation_policy:
      enabled: true
      grace_window: 168h  # 7 days grace period (optional)
    cosmian:
      keys:
        - id: "key-id-2"
          version: 2  # Active key
        - id: "key-id-1"
          version: 1  # Previous key (for dual-read)
```

**Key Settings:**
- `dual_read_window`: Number of previous key versions to attempt during decryption (default: 1)
- `rotation_policy.enabled`: Enable rotation policy tracking and audit events
- `rotation_policy.grace_window`: Optional grace period after rotation (default: 0, uses `dual_read_window`)

### Rotation Policy

The rotation policy provides:

1. **Metrics**: Track rotated reads via `kms_rotated_reads_total` metric
   - Labels: `key_version` (version used), `active_version` (current active version)
2. **Audit Logging**: Decrypt events include metadata when rotated keys are used
   - `rotated_read: true`
   - `key_version_used`: The version used for decryption
   - `active_key_version`: The current active version
3. **Monitoring**: Monitor key rotation status and usage patterns

### Rotation Workflow

**Step 1: Prepare New Key**
- Create a new wrapping key in your KMS (e.g., Cosmian KMS UI)
- Note the new key ID and assign it version number (e.g., version 2)

**Step 2: Update Configuration**
- Add the new key to the `keys` list as the first entry (primary/active)
- Keep previous keys in the list for dual-read support
- Update `dual_read_window` if needed (should be >= number of old keys to support)

**Step 3: Restart Gateway**
- Restart the gateway to load the new configuration
- New objects will be encrypted with the new key version
- Old objects remain accessible via dual-read window

**Step 4: Monitor Rotated Reads**
- Check metrics: `kms_rotated_reads_total{key_version="1",active_version="2"}`
- Review audit logs for `rotated_read: true` events
- Monitor until all objects are accessed and can be re-encrypted (optional)

**Step 5: Optional Cleanup**
- After grace period, remove old keys from configuration
- Old objects encrypted with removed keys will no longer be decryptable
- Ensure all critical objects have been accessed/re-encrypted before cleanup

### Example: Rotation Scenario

```yaml
# Before rotation
encryption:
  key_manager:
    dual_read_window: 1
    cosmian:
      keys:
        - id: "key-v1"
          version: 1

# After rotation (new key v2 is active, v1 still supported)
encryption:
  key_manager:
    dual_read_window: 2
    rotation_policy:
      enabled: true
      grace_window: 168h  # 7 days
    cosmian:
      keys:
        - id: "key-v2"      # Active key
          version: 2
        - id: "key-v1"      # Previous key (dual-read)
          version: 1
```

**Behavior:**
- New objects → Encrypted with key v2
- Old objects (v1) → Decrypted using key v1 (via dual-read)
- Metrics → `kms_rotated_reads_total{key_version="1",active_version="2"}` incremented
- Audit logs → Include `rotated_read: true` for v1 objects

### Monitoring Rotated Reads

**Prometheus Query:**
```promql
# Count rotated reads by key version
sum(rate(kms_rotated_reads_total[5m])) by (key_version, active_version)

# Alert when rotated reads exceed threshold
rate(kms_rotated_reads_total[1h]) > 100
```

**Audit Log Example:**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "event_type": "decrypt",
  "operation": "decrypt",
  "bucket": "my-bucket",
  "key": "object-v1.dat",
  "algorithm": "AES256-GCM",
  "key_version": 1,
  "success": true,
  "metadata": {
    "rotated_read": true,
    "key_version_used": 1,
    "active_key_version": 2
  }
}
```

### Cosmian KMIP Quick Start

Cosmian publishes an all-in-one Docker image that exposes the HTTPS admin UI on port `9998` and KMIP endpoints on ports `5696` (binary) and `9998` (JSON/HTTP). The quickest way to start a local instance is:

```bash
docker run -d --rm --name cosmian-kms \
  -p 5696:5696 -p 9998:9998 --entrypoint cosmian_kms ghcr.io/cosmian/kms:5.14.1
```

**Recommended: JSON/HTTP Endpoint** (tested and verified):
- Endpoint (full URL, recommended): `http://localhost:9998/kmip/2_1`
- Endpoint (base URL, also works): `http://localhost:9998` (path `/kmip/2_1` is automatically appended)
- No TLS client certificates required for HTTP (testing)
- TLS `ca_cert` recommended for HTTPS (production)
- Fully tested and verified in CI

**Advanced: Binary KMIP Endpoint** (requires TLS):
- Endpoint: `localhost:5696`
- Requires proper TLS configuration: `ca_cert`, `client_cert`, `client_key` (mutual TLS)
- Not fully tested in CI - use with caution
- Suitable for production with proper certificate management

Once the container is running:
1. Access the Cosmian KMS UI at http://localhost:9998/ui
2. Create a wrapping key via the UI and note its identifier
3. Configure the gateway with the key ID under `encryption.key_manager.cosmian.keys`

Refer to the [Cosmian installation guide](https://docs.cosmian.com/key_management_system/installation/installation_getting_started/?utm_source=openai) for production-grade TLS and identity settings.

The repository ships with integration tests (`test/cosmian_kms_integration_test.go`) that exercise the JSON/HTTP KMIP flow. These tests run as part of `go test ./...` or `make test-comprehensive` and ensure that wrapping/unwrapping as well as metadata propagation work correctly.

## Implementing a Custom KMS

To create a KMS-compatible system, implement the `KeyManager` interface. Here's how:

### Step 1: Implement the Interface

```go
type YourKMS struct {
    client kmip.Client
    active wrappingKey
}

func (k *YourKMS) Provider() string {
    return "your-kms"
}

func (k *YourKMS) WrapKey(ctx context.Context, plaintext []byte, _ map[string]string) (*crypto.KeyEnvelope, error) {
    ciphertext, err := k.client.Encrypt(ctx, k.active.ID, plaintext)
    if err != nil {
        return nil, err
    }
    return &crypto.KeyEnvelope{
        KeyID:      k.active.ID,
        KeyVersion: k.active.Version,
        Provider:   k.Provider(),
        Ciphertext: ciphertext,
    }, nil
}

func (k *YourKMS) UnwrapKey(ctx context.Context, env *crypto.KeyEnvelope, _ map[string]string) ([]byte, error) {
    return k.client.Decrypt(ctx, env.KeyID, env.Ciphertext)
}

func (k *YourKMS) ActiveKeyVersion(ctx context.Context) (int, error) {
    return k.active.Version, nil
}

func (k *YourKMS) Close(ctx context.Context) error {
    return k.client.Close(ctx)
}
```

### Step 2: Integration Points

The gateway calls the KeyManager in these scenarios:

1. **Encryption**: Calls `GetActiveKey()` to get the current password
2. **Decryption**: Uses the metadata-stored envelope to call `UnwrapKey()`
3. **Key Rotation**: Uses `RotateKey()` when keys need to be rotated

### Step 3: Key Versioning Strategy

The gateway stores key version information in object metadata:

- **Metadata Key**: `x-amz-meta-encryption-key-version`
- **Format**: Integer version number (1, 2, 3, ...)

Your KMS should:
- Assign sequential version numbers
- Track which version is active
- Retain old versions for decryption
- Support deactivating old versions

### Step 4: Password/Key Format

The gateway expects:
- **Type**: String (UTF-8)
- **Length**: Minimum 12 characters
- **Usage**: Used as-is for PBKDF2 key derivation

Your KMS can:
- Generate random passwords automatically
- Use passwords provided by administrators
- Derive passwords from other sources (master keys, etc.)

## Example: AWS KMS Integration (Conceptual - Not Yet Implemented)

> **⚠️ This is a conceptual example only.** AWS KMS adapter is planned for v1.0. See [V1.0-KMS-2](../issues/v1.0-issues.md#v10-kms-2-aws-kms-adapter) for implementation details.

Here's a conceptual example of how AWS KMS integration would work:

```go
package awskms

import (
    "github.com/aws/aws-sdk-go-v2/service/kms"
    "github.com/kenneth/s3-encryption-gateway/internal/crypto"
)

type AWSKMSManager struct {
    client     *kms.Client
    keyID      string
    keyVersions map[int]string
    currentVersion int
}

func (k *AWSKMSManager) GetActiveKey() (string, int, error) {
    // Decrypt the current version's key from AWS KMS
    result, err := k.client.Decrypt(context.TODO(), &kms.DecryptInput{
        CiphertextBlob: k.getCiphertextForVersion(k.currentVersion),
    })
    if err != nil {
        return "", 0, err
    }
    
    return string(result.Plaintext), k.currentVersion, nil
}

func (k *AWSKMSManager) RotateKey(newPassword string, deactivateOld bool) error {
    // Encrypt new password with AWS KMS
    encryptResult, err := k.client.Encrypt(context.TODO(), &kms.EncryptInput{
        KeyId:     &k.keyID,
        Plaintext: []byte(newPassword),
    })
    if err != nil {
        return err
    }
    
    // Store new version
    newVersion := k.currentVersion + 1
    k.keyVersions[newVersion] = base64.StdEncoding.EncodeToString(encryptResult.CiphertextBlob)
    k.currentVersion = newVersion
    
    // Optionally disable old versions in AWS KMS
    if deactivateOld {
        // Implement key alias rotation or disable old keys
    }
    
    return nil
}
```

## Example: HashiCorp Vault Integration (Conceptual - Not Yet Implemented)

> **⚠️ This is a conceptual example only.** Vault Transit adapter is planned for v1.0. See [V1.0-KMS-3](../issues/v1.0-issues.md#v10-kms-3-hashicorp-vault-transit-adapter) for implementation details.

```go
package vaultkms

import (
    "github.com/hashicorp/vault/api"
    "github.com/kenneth/s3-encryption-gateway/internal/crypto"
)

type VaultKMSManager struct {
    client *api.Client
    path   string // e.g., "secret/data/s3-gateway-keys"
}

func (v *VaultKMSManager) GetActiveKey() (string, int, error) {
    secret, err := v.client.Logical().Read(v.path + "/active")
    if err != nil {
        return "", 0, err
    }
    
    password := secret.Data["password"].(string)
    version := int(secret.Data["version"].(float64))
    
    return password, version, nil
}
```

## Example: Database-Backed KMS

```go
package dbkms

import (
    "database/sql"
    "github.com/kenneth/s3-encryption-gateway/internal/crypto"
)

type DatabaseKMSManager struct {
    db *sql.DB
}

func (d *DatabaseKMSManager) GetActiveKey() (string, int, error) {
    var password string
    var version int
    
    err := d.db.QueryRow(`
        SELECT password, version 
        FROM encryption_keys 
        WHERE active = true 
        ORDER BY version DESC 
        LIMIT 1
    `).Scan(&password, &version)
    
    return password, version, err
}

func (d *DatabaseKMSManager) RotateKey(newPassword string, deactivateOld bool) error {
    tx, err := d.db.Begin()
    if err != nil {
        return err
    }
    defer tx.Rollback()
    
    // Get next version
    var maxVersion int
    tx.QueryRow("SELECT COALESCE(MAX(version), 0) FROM encryption_keys").Scan(&maxVersion)
    newVersion := maxVersion + 1
    
    // Insert new key
    _, err = tx.Exec(`
        INSERT INTO encryption_keys (version, password, active, created_at)
        VALUES ($1, $2, true, NOW())
    `, newVersion, newPassword)
    if err != nil {
        return err
    }
    
    // Deactivate old keys if requested
    if deactivateOld {
        _, err = tx.Exec(`
            UPDATE encryption_keys 
            SET active = false, rotated_at = NOW()
            WHERE active = true AND version < $1
        `, newVersion)
        if err != nil {
            return err
        }
    }
    
    return tx.Commit()
}
```

## Configuration

Enable KMS mode in your configuration:

```yaml
encryption:
  password: "initial-password-or-kms-master-key"  # Still required for initialization
  key_manager:
    enabled: true  # Enable KMS mode
```

Or via environment variable:

```bash
export KEY_MANAGER_ENABLED=true
export ENCRYPTION_PASSWORD="your-initial-password"
```

## Key Rotation Workflow (Updated)

When using KMS mode with external KMS (e.g., Cosmian KMIP), the rotation workflow is:

1. **Current State**: All objects encrypted with key version 1
2. **Create New Key**: Create a new wrapping key in your KMS (e.g., via Cosmian KMS UI)
   - Assign it version 2
   - Note the key ID
3. **Update Configuration**: Add new key to `encryption.key_manager.cosmian.keys` as first entry
   - Keep old key(s) in the list for dual-read support
   - Set `dual_read_window` appropriately
4. **Restart Gateway**: Restart to load new configuration
   - New objects → Encrypted with version 2
   - Old objects → Still decryptable with version 1 (via dual-read)
5. **Monitor**: Track rotated reads via metrics and audit logs
6. **Optional Cleanup**: After grace period, remove old keys from configuration
   - Ensure all critical objects have been accessed/re-encrypted
   - Objects encrypted with removed keys will no longer be decryptable

See the [Dual-Read Window and Key Rotation](#dual-read-window-and-key-rotation) section above for detailed configuration and monitoring guidance.

## Best Practices

### Security
- **Never log passwords**: Keys should be encrypted at rest
- **Use secure storage**: Store keys in encrypted databases, HSMs, or cloud KMS
- **Access control**: Implement proper access controls for key retrieval
- **Audit logging**: Log all key access and rotation events

### Performance
- **Key caching**: Cache active keys in memory (with TTL)
- **Connection pooling**: For database-backed KMS
- **Retry logic**: Handle transient failures gracefully

### Operations
- **Key rotation schedule**: Establish regular rotation schedule
- **Backup keys**: Always backup keys before rotation
- **Version retention**: Keep old versions until all objects are migrated
- **Monitoring**: Monitor key usage and rotation status

## Testing Your KMS

Create a test to verify your KMS implementation:

```go
func TestYourKMS(t *testing.T) {
    kms := NewYourKMS(...)
    
    // Test GetActiveKey
    key, version, err := kms.GetActiveKey()
    assert.NoError(t, err)
    assert.GreaterOrEqual(t, len(key), 12)
    assert.Greater(t, version, 0)
    
    // Test RotateKey
    err = kms.RotateKey("new-password-123", false)
    assert.NoError(t, err)
    
    // Verify new key is active
    newKey, newVersion, err := kms.GetActiveKey()
    assert.NoError(t, err)
    assert.Equal(t, "new-password-123", newKey)
    assert.Greater(t, newVersion, version)
    
    // Test Wrap/Unwrap cycle
    env, err := kms.WrapKey(ctx, []byte("plaintext-dek"), nil)
    assert.NoError(t, err)
    plaintext, err := kms.UnwrapKey(ctx, env, nil)
    assert.NoError(t, err)
    assert.Equal(t, []byte("plaintext-dek"), plaintext)
}
```

## Migration from Single Password Mode

To migrate from single password to KMS mode:

1. **Backup**: Ensure you have backups of all encrypted objects
2. **Enable KMS**: Set `key_manager.enabled: true` in config
3. **Initialize**: Start with your current password
4. **Rotate**: After verifying everything works, rotate to a new key
5. **Monitor**: Watch for decryption failures (indicates version issues)

The gateway will continue to work with objects encrypted with the original password, and new objects will use the new key.

## Troubleshooting

### "no active key found"
- Check that your KMS is returning valid keys
- Verify the key meets minimum length requirements (12 chars)

### Decryption failures after rotation
- Ensure old key versions are still accessible
- Check that `WrapKey()/UnwrapKey()` round-trip correctly
- Verify metadata includes correct version number

### Performance issues
- Implement key caching in your KMS
- Use connection pooling for remote KMS services
- Monitor KMS response times

## Additional Resources

- See `internal/crypto/keymanager.go` for the reference implementation
- See `internal/crypto/keymanager_test.go` for test examples
- See [`DEVELOPMENT_NOTES.md`](DEVELOPMENT_NOTES.md) for development notes on key rotation
