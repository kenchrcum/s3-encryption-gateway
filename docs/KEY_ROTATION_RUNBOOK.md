# Key Rotation Runbook

This runbook provides step-by-step procedures for rotating encryption keys in the S3 Encryption Gateway when using external KMS (Key Management System) providers.

## Prerequisites

- Access to the KMS provider (e.g., Cosmian KMS UI)
- Gateway configuration file access
- Monitoring/alerting access (Prometheus, audit logs)
- Backup of current configuration
- Understanding of dual-read window concept

## Pre-Rotation Checklist

- [ ] Backup current gateway configuration
- [ ] Verify KMS connectivity and health (`/ready` endpoint)
- [ ] Review current key usage metrics
- [ ] Identify critical objects that must remain accessible
- [ ] Plan maintenance window (if required)
- [ ] Notify stakeholders of rotation schedule
- [ ] Ensure monitoring/alerting is configured

## Rotation Procedure

### Step 1: Create New Wrapping Key

**For Cosmian KMIP:**

1. Access Cosmian KMS UI (typically `http://kms-host:9998/ui`)
2. Navigate to **Keys** section
3. Click **Create New Key**
4. Configure key:
   - **Algorithm**: AES-256 (or as per policy)
   - **Key Type**: Symmetric
   - **Usage**: Encryption/Decryption
5. **Save the key ID** (you'll need this for configuration)
6. Note the key creation timestamp

**For Other KMS Providers:**
- Follow provider-specific procedures to create a new wrapping key
- Ensure the key supports encryption/decryption operations
- Record the key identifier/ARN

### Step 2: Update Gateway Configuration

1. **Backup current configuration:**
   ```bash
   cp config.yaml config.yaml.backup-$(date +%Y%m%d)
   ```

2. **Edit configuration file:**
   ```yaml
   encryption:
     key_manager:
       enabled: true
       provider: "cosmian"  # or your provider
       dual_read_window: 2  # Ensure this covers old keys
       rotation_policy:
         enabled: true
         grace_window: 168h  # 7 days (adjust as needed)
       cosmian:
         keys:
           # NEW KEY (active) - add as first entry
           - id: "new-key-id-here"
             version: 2
           # OLD KEY (for dual-read) - keep in list
           - id: "old-key-id-here"
             version: 1
   ```

3. **Verify configuration:**
   ```bash
   # Validate YAML syntax
   yamllint config.yaml
   
   # Test configuration loading
   ./s3-encryption-gateway --config config.yaml --validate
   ```

### Step 3: Deploy Updated Configuration

**For Kubernetes/Helm:**
```bash
# Update values.yaml or use --set
helm upgrade s3-encryption-gateway ./helm/s3-encryption-gateway \
  --set encryption.keyManager.cosmian.keys[0].id="new-key-id" \
  --set encryption.keyManager.cosmian.keys[0].version=2 \
  --set encryption.keyManager.dualReadWindow=2

# Or update ConfigMap/Secret directly
kubectl apply -f config.yaml
kubectl rollout restart deployment/s3-encryption-gateway
```

**For Docker/Standalone:**
```bash
# Copy new config
cp config.yaml /etc/s3-encryption-gateway/

# Restart service
systemctl restart s3-encryption-gateway
# or
docker restart s3-encryption-gateway
```

### Step 4: Verify Rotation

1. **Check gateway health:**
   ```bash
   curl http://gateway:8080/ready
   # Should return: {"status":"ready","timestamp":"..."}
   ```

2. **Verify new key is active:**
   ```bash
   # Check logs for key manager initialization
   kubectl logs deployment/s3-encryption-gateway | grep "key.*version"
   ```

3. **Test encryption with new key:**
   ```bash
   # Upload a test object
   aws s3 cp test.txt s3://bucket/test-rotation.txt \
     --endpoint-url http://gateway:8080
   
   # Check metadata for key version
   aws s3api head-object --bucket bucket --key test-rotation.txt \
     --endpoint-url http://gateway:8080 \
     --query 'Metadata."x-amz-meta-encryption-key-version"'
   # Should return: "2"
   ```

4. **Test decryption of old objects:**
   ```bash
   # Download an object encrypted with old key
   aws s3 cp s3://bucket/old-object.txt /tmp/old-object.txt \
     --endpoint-url http://gateway:8080
   
   # Should succeed (dual-read window)
   ```

### Step 5: Monitor Rotated Reads

**Check Prometheus Metrics:**
```promql
# Current rotated read rate
rate(kms_rotated_reads_total[5m])

# Rotated reads by key version
sum(rate(kms_rotated_reads_total[1h])) by (key_version, active_version)

# Alert query (if rotated reads exceed threshold)
rate(kms_rotated_reads_total[1h]) > 100
```

**Check Audit Logs:**
```bash
# Search for rotated read events
kubectl logs deployment/s3-encryption-gateway | \
  jq 'select(.metadata.rotated_read == true)'

# Count rotated reads
kubectl logs deployment/s3-encryption-gateway | \
  jq 'select(.metadata.rotated_read == true)' | wc -l
```

**Expected Behavior:**
- New objects encrypted with key version 2
- Old objects (version 1) decrypt successfully
- Metrics show `kms_rotated_reads_total{key_version="1",active_version="2"}` incrementing
- Audit logs show `rotated_read: true` for version 1 objects

### Step 6: Monitor Grace Period

During the grace period (if configured):

1. **Track rotated read trends:**
   - Monitor if rotated reads are decreasing (objects being re-encrypted)
   - Identify objects that haven't been accessed
   - Plan for re-encryption of critical objects

2. **Review access patterns:**
   - Identify frequently accessed objects
   - Prioritize re-encryption of hot objects
   - Document cold objects for later cleanup

3. **Set up alerts:**
   ```yaml
   # Prometheus alert rule example
   - alert: HighRotatedReadRate
     expr: rate(kms_rotated_reads_total[1h]) > 1000
     for: 1h
     annotations:
       summary: "High rate of rotated key reads detected"
       description: "{{ $value }} rotated reads per hour"
   ```

### Step 7: Post-Rotation Cleanup (Optional)

**After grace period expires:**

1. **Verify all critical objects accessed:**
   ```bash
   # Check audit logs for last access times
   kubectl logs deployment/s3-encryption-gateway | \
     jq 'select(.metadata.key_version_used == 1) | .key' | \
     sort -u > old-objects.txt
   ```

2. **Re-encrypt critical objects (if needed):**
   ```bash
   # Copy objects to trigger re-encryption
   while read key; do
     aws s3 cp s3://bucket/$key s3://bucket/$key.new \
       --endpoint-url http://gateway:8080
     aws s3 mv s3://bucket/$key.new s3://bucket/$key \
       --endpoint-url http://gateway:8080
   done < critical-objects.txt
   ```

3. **Remove old keys from configuration:**
   ```yaml
   encryption:
     key_manager:
       cosmian:
         keys:
           # Only keep active key
           - id: "new-key-id-here"
             version: 2
           # Remove old keys
   ```

4. **Deploy updated configuration:**
   ```bash
   # Same as Step 3
   kubectl apply -f config.yaml
   kubectl rollout restart deployment/s3-encryption-gateway
   ```

5. **Verify old keys removed:**
   - Objects encrypted with removed keys will fail to decrypt
   - Ensure all critical objects have been re-encrypted
   - Monitor for decryption errors

## Rollback Procedure

If rotation causes issues:

1. **Immediate rollback:**
   ```bash
   # Restore previous configuration
   cp config.yaml.backup-YYYYMMDD config.yaml
   
   # Restart gateway
   kubectl rollout restart deployment/s3-encryption-gateway
   ```

2. **Verify rollback:**
   - Check gateway health
   - Test encryption/decryption
   - Verify old key is active again

3. **Investigate issues:**
   - Review logs for errors
   - Check KMS connectivity
   - Verify key permissions
   - Review configuration syntax

## Troubleshooting

### Issue: Gateway fails to start after rotation

**Symptoms:**
- Gateway pod in CrashLoopBackOff
- Health checks failing

**Resolution:**
1. Check configuration syntax: `yamllint config.yaml`
2. Verify KMS connectivity: `curl http://kms:9998/health`
3. Check key IDs are correct
4. Review logs: `kubectl logs deployment/s3-encryption-gateway`

### Issue: Old objects fail to decrypt

**Symptoms:**
- Decryption errors for objects encrypted with old keys
- `kms_rotated_reads_total` not incrementing

**Resolution:**
1. Verify old keys are still in configuration
2. Check `dual_read_window` is sufficient
3. Verify KMS still has access to old keys
4. Check key permissions in KMS

### Issue: New objects encrypted with wrong key

**Symptoms:**
- New objects show old key version in metadata
- `ActiveKeyVersion()` returns wrong version

**Resolution:**
1. Verify new key is first in `keys` list
2. Check key version numbers are correct
3. Restart gateway to reload configuration
4. Verify KMS key is accessible

### Issue: High rotated read rate

**Symptoms:**
- `kms_rotated_reads_total` increasing rapidly
- Performance degradation

**Resolution:**
1. Consider increasing `dual_read_window`
2. Plan re-encryption of frequently accessed objects
3. Monitor KMS performance
4. Review grace period settings

## Best Practices

1. **Schedule rotations regularly:**
   - Quarterly or as per security policy
   - During low-traffic periods
   - With stakeholder notification

2. **Maintain key history:**
   - Keep at least 2-3 previous key versions
   - Document key creation dates
   - Track key usage patterns

3. **Monitor continuously:**
   - Set up alerts for rotated reads
   - Review audit logs regularly
   - Track key usage metrics

4. **Test rotation process:**
   - Practice in non-production first
   - Document any issues encountered
   - Refine procedures based on experience

5. **Document everything:**
   - Key IDs and versions
   - Rotation dates
   - Configuration changes
   - Issues and resolutions

## Object Lock Interaction (V0.6-S3-2)

Objects written through the gateway with an S3 Object Lock
configuration (`x-amz-object-lock-mode=COMPLIANCE` in particular) cannot
be rewritten until the retention period expires. Because the gateway
rotates keys by re-encrypting and rewriting the ciphertext, locked
objects are **skipped** by the rotation worker:

- The worker classifies backend `AccessDenied` with a retention code
  as a non-retryable skip, emits a structured log entry, and
  increments the `gateway_rotation_skipped_locked_total` Prometheus
  counter.
- Governance-mode objects are also skipped until V0.6-CFG-1 lands the
  admin-gated `x-amz-bypass-governance-retention` path. The gateway
  refuses the bypass header in v0.6 (see ADR 0008).

**Operator implications:**

- Monitor `gateway_rotation_skipped_locked_total`. A non-zero value
  means one or more KEK versions cannot be retired until the
  referenced locked objects expire.
- **Align KMS/KEK retention with the maximum Object Lock retention
  window in use.** Retiring a KEK while a locked object still
  references it leaves the ciphertext on disk with no key to unwrap
  it. The backend's retention guarantees byte persistence; it does
  not guarantee readable-data persistence.
- When a rotation campaign finishes with skips, record the KEK
  versions that could not be retired and their earliest retirement
  date (max retain-until across all skipped objects that reference
  that version). Do not retire those KEK versions before that date.

See `docs/adr/0008-object-lock-ciphertext-semantics.md` for the
full ciphertext-locking model and provider-support matrix.

## Related Documentation

- [KMS Compatibility Guide](KMS_COMPATIBILITY.md) - Detailed KMS integration guide
- [Configuration Reference](../README.md#configuration) - Full configuration options
- [Monitoring Guide](../docs/DEPLOYMENT.md#monitoring) - Metrics and monitoring setup

