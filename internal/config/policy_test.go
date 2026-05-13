package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyLoadingAndMatching(t *testing.T) {
	// Create temporary policy file
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy1.yaml")
	policyContent := `
id: "tenant-a"
buckets: 
  - "tenant-a-*"
  - "shared-bucket"
encryption:
  password: "tenant-a-password-123456"
  preferred_algorithm: "ChaCha20-Poly1305"
  chunked_mode: false
compression:
  enabled: true
  algorithm: "zstd"
  min_size: 512
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)

	// Initialize PolicyManager
	pm := NewPolicyManager()
	err = pm.LoadPolicies([]string{filepath.Join(tmpDir, "*.yaml")})
	require.NoError(t, err)

	// Test matching
	tests := []struct {
		bucket      string
		shouldMatch bool
		policyID    string
	}{
		{"tenant-a-data", true, "tenant-a"},
		{"tenant-a-logs", true, "tenant-a"},
		{"shared-bucket", true, "tenant-a"},
		{"other-bucket", false, ""},
		{"tenant-b-data", false, ""},
	}

	for _, tt := range tests {
		policy := pm.GetPolicyForBucket(tt.bucket)
		if tt.shouldMatch {
			require.NotNil(t, policy, "Expected policy match for bucket %s", tt.bucket)
			assert.Equal(t, tt.policyID, policy.ID)
		} else {
			assert.Nil(t, policy, "Expected no policy match for bucket %s", tt.bucket)
		}
	}
}

// TestBucketRequiresEncryption verifies BucketRequiresEncryption returns
// the correct boolean for matching and non-matching buckets.
func TestBucketRequiresEncryption(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "require-enc.yaml")
	policyContent := `
id: "require-enc-policy"
buckets:
  - "encrypted-*"
require_encryption: true
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)

	pm := NewPolicyManager()
	err = pm.LoadPolicies([]string{filepath.Join(tmpDir, "*.yaml")})
	require.NoError(t, err)

	tests := []struct {
		bucket string
		want   bool
	}{
		{"encrypted-bucket", true},
		{"other-bucket", false},
		{"encrypted-files", true},
	}

	for _, tt := range tests {
		got := pm.BucketRequiresEncryption(tt.bucket)
		assert.Equal(t, tt.want, got, "BucketRequiresEncryption(%q)", tt.bucket)
	}

	// nil manager should return false (not panic)
	var nilPM *PolicyManager
	assert.False(t, nilPM.BucketRequiresEncryption("any-bucket"))
}

// TestBucketEncryptsMultipart verifies BucketEncryptsMultipart returns the
// correct boolean for matching and non-matching buckets.
// Default is true: buckets with no matching policy or a policy that omits the
// field are encrypted; only an explicit false opts a bucket out.
func TestBucketEncryptsMultipart(t *testing.T) {
	tmpDir := t.TempDir()

	// Policy with explicit true for specific buckets, explicit false for others.
	policyFile := filepath.Join(tmpDir, "mpu-enc.yaml")
	policyContent := `
id: "mpu-enc-policy"
buckets:
  - "mpu-bucket"
  - "multi-*"
encrypt_multipart_uploads: true
`
	policyFileOff := filepath.Join(tmpDir, "mpu-off.yaml")
	policyContentOff := `
id: "mpu-off-policy"
buckets:
  - "plain-bucket"
encrypt_multipart_uploads: false
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)
	err = os.WriteFile(policyFileOff, []byte(policyContentOff), 0644)
	require.NoError(t, err)

	pm := NewPolicyManager()
	err = pm.LoadPolicies([]string{filepath.Join(tmpDir, "*.yaml")})
	require.NoError(t, err)

	tests := []struct {
		bucket string
		want   bool
	}{
		{"mpu-bucket", true},          // explicit true
		{"multi-upload", true},        // explicit true via glob
		{"plain-bucket", false},       // explicit false
		{"other-bucket", true},        // no matching policy → default true
	}

	for _, tt := range tests {
		got := pm.BucketEncryptsMultipart(tt.bucket)
		assert.Equal(t, tt.want, got, "BucketEncryptsMultipart(%q)", tt.bucket)
	}

	// nil manager should return true (safe default)
	var nilPM *PolicyManager
	assert.True(t, nilPM.BucketEncryptsMultipart("any-bucket"))
}

// TestAnyPolicyRequiresMPUEncryption verifies the boolean aggregate.
// Returns true when at least one policy has encrypt_multipart_uploads omitted
// (default true) or set explicitly to true.
// Returns false only when every loaded policy explicitly sets it to false,
// or when no policies are loaded.
func TestAnyPolicyRequiresMPUEncryption(t *testing.T) {
	tmpDir := t.TempDir()

	// No policies loaded → false (Valkey not required if there are no policies at all).
	pm0 := NewPolicyManager()
	assert.False(t, pm0.AnyPolicyRequiresMPUEncryption(), "expected false with no policies loaded")

	// Policy with field omitted → default true → AnyPolicyRequiresMPUEncryption = true.
	policyFile := filepath.Join(tmpDir, "default.yaml")
	policyContent := `
id: "plain-policy"
buckets:
  - "plain-bucket"
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)

	pm := NewPolicyManager()
	err = pm.LoadPolicies([]string{policyFile})
	require.NoError(t, err)
	assert.True(t, pm.AnyPolicyRequiresMPUEncryption(), "expected true when policy omits field (default true)")

	// Policy with explicit false → false.
	policyFileOff := filepath.Join(tmpDir, "off.yaml")
	policyContentOff := `
id: "off-policy"
buckets:
  - "other-bucket"
encrypt_multipart_uploads: false
`
	err = os.WriteFile(policyFileOff, []byte(policyContentOff), 0644)
	require.NoError(t, err)

	pmOff := NewPolicyManager()
	err = pmOff.LoadPolicies([]string{policyFileOff})
	require.NoError(t, err)
	assert.False(t, pmOff.AnyPolicyRequiresMPUEncryption(), "expected false when all policies explicitly set false")

	// Mix: one explicit false + one explicit true → true.
	policyFileOn := filepath.Join(tmpDir, "on.yaml")
	policyContentOn := `
id: "on-policy"
buckets:
  - "mpu-bucket"
encrypt_multipart_uploads: true
`
	err = os.WriteFile(policyFileOn, []byte(policyContentOn), 0644)
	require.NoError(t, err)

	pmMix := NewPolicyManager()
	err = pmMix.LoadPolicies([]string{policyFileOff, policyFileOn})
	require.NoError(t, err)
	assert.True(t, pmMix.AnyPolicyRequiresMPUEncryption(), "expected true when at least one policy enables MPU encryption")

	// nil manager should return false
	var nilPM *PolicyManager
	assert.False(t, nilPM.AnyPolicyRequiresMPUEncryption())
}

// TestBucketDisallowsLockBypass verifies BucketDisallowsLockBypass.
func TestBucketDisallowsLockBypass(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "lock.yaml")
	policyContent := `
id: "lock-policy"
buckets:
  - "locked-bucket"
disallow_lock_bypass: true
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)

	pm := NewPolicyManager()
	err = pm.LoadPolicies([]string{filepath.Join(tmpDir, "*.yaml")})
	require.NoError(t, err)

	assert.True(t, pm.BucketDisallowsLockBypass("locked-bucket"))
	assert.False(t, pm.BucketDisallowsLockBypass("other-bucket"))
}

// TestPolicyManager_NilSafe verifies methods on a nil PolicyManager that have
// explicit nil guards do not panic. GetPolicyForBucket is not nil-safe by
// design (it acquires a lock), so it is excluded from this test.
// BucketEncryptsMultipart returns true on a nil manager (safe default: encrypt).
func TestPolicyManager_NilSafe(t *testing.T) {
	var pm *PolicyManager
	assert.False(t, pm.BucketRequiresEncryption("any-bucket"))
	assert.True(t, pm.BucketEncryptsMultipart("any-bucket")) // default-on: nil manager = encrypt
	assert.False(t, pm.AnyPolicyRequiresMPUEncryption())
}

// TestLoadPolicies_MissingRequiredFields verifies that policies with missing
// required fields (ID, buckets) are rejected.
func TestLoadPolicies_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name: "missing ID",
			content: `
buckets:
  - "test-bucket"
`,
		},
		{
			name: "missing buckets",
			content: `
id: "test-policy"
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			policyFile := filepath.Join(tmpDir, "bad-policy.yaml")
			err := os.WriteFile(policyFile, []byte(tt.content), 0644)
			require.NoError(t, err)

			pm := NewPolicyManager()
			err = pm.LoadPolicies([]string{filepath.Join(tmpDir, "*.yaml")})
			assert.Error(t, err, "expected error for policy with missing required field")
		})
	}
}

func TestPolicyApplication(t *testing.T) {
	// Base config
	baseConfig := &Config{
		Encryption: EncryptionConfig{
			Password:           "base-password",
			PreferredAlgorithm: "AES256-GCM",
			ChunkedMode:        true,
			ChunkSize:          65536,
		},
		Compression: CompressionConfig{
			Enabled: false,
		},
	}

	// Policy
	policy := &PolicyConfig{
		ID: "test-policy",
		Encryption: &EncryptionConfig{
			Password:           "policy-password",
			PreferredAlgorithm: "ChaCha20-Poly1305",
			// ChunkedMode and ChunkSize not set, should retain zero values if struct default?
			// The Unmarshal will leave them as zero values (false, 0).
			// But ApplyToConfig logic manually merges specific fields for Encryption.
		},
		Compression: &CompressionConfig{
			Enabled:   true,
			Algorithm: "gzip",
		},
	}

	// Apply policy
	newConfig := policy.ApplyToConfig(baseConfig)

	// Verify base config not modified
	assert.Equal(t, "base-password", baseConfig.Encryption.Password)
	assert.False(t, baseConfig.Compression.Enabled)

	// Verify new config has overrides
	assert.Equal(t, "policy-password", newConfig.Encryption.Password)
	assert.Equal(t, "ChaCha20-Poly1305", newConfig.Encryption.PreferredAlgorithm)
	
	// Verify manually merged fields retained base value if not in policy?
	// Wait, ApplyToConfig creates a shallow copy then:
	// 1. Replaces whole Compression struct (so base Compression lost)
	// 2. Encryption struct logic:
	//    if p.Encryption != nil {
	//        enc := base.Encryption (copy)
	//        if p.Encryption.Password != "" { enc.Password = p.Encryption.Password }
	//        ...
	//        newConfig.Encryption = enc
	//    }
	
	// So for Encryption, fields NOT manually merged should be retained from base.
	// Let's check which fields are manually merged in policy.go.
	// Password, PreferredAlgorithm, KeyManager (if enabled).
	// ChunkedMode is NOT manually merged in my implementation of ApplyToConfig!
	// Let's check policy.go content.
	
	// In policy.go:
	/*
		if p.Encryption != nil {
			// Start with base encryption config
			enc := base.Encryption
			// Override fields that are set in policy
			
			// Let's do a manual merge for common fields to be safe and useful
			if p.Encryption.Password != "" {
				enc.Password = p.Encryption.Password
			}
			if p.Encryption.PreferredAlgorithm != "" {
				enc.PreferredAlgorithm = p.Encryption.PreferredAlgorithm
			}
			// If KeyManager is explicitly configured in policy (Enabled is true or Provider is set), override it
			if p.Encryption.KeyManager.Enabled || p.Encryption.KeyManager.Provider != "" {
				enc.KeyManager = p.Encryption.KeyManager
			}
			
			newConfig.Encryption = enc
		}
	*/
	
	// So ChunkedMode from base SHOULD be preserved because `enc := base.Encryption` copies it, 
	// and we don't overwrite it from policy (since we didn't add manual merge for it, nor replace entire struct).
	
	assert.Equal(t, true, newConfig.Encryption.ChunkedMode)
	assert.Equal(t, 65536, newConfig.Encryption.ChunkSize)

	// Verify Compression replaced completely
	assert.True(t, newConfig.Compression.Enabled)
	assert.Equal(t, "gzip", newConfig.Compression.Algorithm)
}

