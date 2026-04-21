//go:build integration
// +build integration

package test

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"strings"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	s3sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/kenneth/s3-encryption-gateway/internal/mpu"
)

const (
	testValkeyAddr     = "localhost:6379"
	testMPUPassword    = "integration-test-password-32char"
	testMPUTTLSeconds  = 3600
)

// valkeyDBForTest picks a Valkey DB (0–15) based on the test name hash.
// Tests rely on unique uploadIDs rather than DB isolation; this is a
// best-effort extra separation layer only.
func valkeyDBForTest(t *testing.T) int {
	t.Helper()
	h := fnv.New32a()
	_, _ = h.Write([]byte(t.Name()))
	return int(h.Sum32()%15) + 1 // 1–15; leave 0 for interactive use
}

// valkeyAddr returns the Valkey address for integration tests, defaulting to
// localhost:6379 but honoring VALKEY_ADDR if set.
func valkeyAddr() string {
	if addr := os.Getenv("VALKEY_ADDR"); addr != "" {
		return addr
	}
	return testValkeyAddr
}

// NewTestMPUStateStore constructs a ValkeyStateStore pointed at the local
// Valkey instance. The test is skipped if Valkey is unreachable.
// t.Cleanup flushes the per-test DB on exit.
func NewTestMPUStateStore(t *testing.T) mpu.StateStore {
	t.Helper()
	db := valkeyDBForTest(t)
	cfg := config.ValkeyConfig{
		Addr:                   valkeyAddr(),
		DB:                     db,
		InsecureAllowPlaintext: true,
		TLS:                    config.ValkeyTLSConfig{Enabled: false},
		TTLSeconds:             testMPUTTLSeconds,
		DialTimeout:            3 * time.Second,
		ReadTimeout:            2 * time.Second,
		WriteTimeout:           2 * time.Second,
		PoolSize:               4,
	}
	store, err := mpu.NewValkeyStateStore(context.Background(), cfg)
	if err != nil {
		t.Skipf("Valkey unavailable at %s (start with docker-compose up -d valkey): %v", valkeyAddr(), err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

// NewTestPasswordKeyManager creates a PasswordKeyManager for integration tests.
func NewTestPasswordKeyManager(t *testing.T) crypto.KeyManager {
	t.Helper()
	km, err := crypto.NewPasswordKeyManager(testMPUPassword)
	if err != nil {
		t.Fatalf("NewPasswordKeyManager: %v", err)
	}
	return km
}

// NewRawBackendS3Client returns an AWS SDK v2 S3 client configured to talk
// directly to the MinIO backend (bypassing the gateway). Use this to inspect
// at-rest ciphertext in encrypted-MPU tests.
func NewRawBackendS3Client(t *testing.T, m *MinIOTestServer) *s3sdk.Client {
	t.Helper()
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(m.AccessKey, m.SecretKey, ""),
		),
	)
	if err != nil {
		t.Fatalf("aws config: %v", err)
	}
	return s3sdk.NewFromConfig(awsCfg, func(o *s3sdk.Options) {
		o.BaseEndpoint = &m.Endpoint
		o.UsePathStyle = true
	})
}

// CreateBucketForTest creates a bucket directly on the MinIO backend using the
// AWS SDK v2 CreateBucket API. Idempotent: if the bucket already exists, no
// error is returned. Used by V0.6-S3-3 integration tests to provision per-test
// buckets without shelling out to the aws CLI.
func CreateBucketForTest(t *testing.T, m *MinIOTestServer, bucket string) {
	t.Helper()
	cl := NewRawBackendS3Client(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := cl.CreateBucket(ctx, &s3sdk.CreateBucketInput{Bucket: &bucket})
	if err != nil {
		msg := err.Error()
		// Idempotent: swallow "already exists" / "already owned" conditions.
		if !strings.Contains(msg, "BucketAlreadyOwnedByYou") && !strings.Contains(msg, "BucketAlreadyExists") {
			t.Fatalf("CreateBucketForTest(%s): %v", bucket, err)
		}
	}
}

// NewTestPolicyManager writes each yaml document to its own file (matching
// LoadPolicies' one-policy-per-file contract) and loads them. Accepts either
// (a) a single multi-policy YAML string separated by --- markers, or
// (b) a slice of individual policy YAML strings.
func NewTestPolicyManager(t *testing.T, policyYAMLs ...string) *config.PolicyManager {
	t.Helper()
	dir := t.TempDir()
	paths := make([]string, 0, len(policyYAMLs))
	for i, policyYAML := range policyYAMLs {
		// Split on YAML document separators (---), filter out empty docs.
		docs := strings.Split(policyYAML, "\n---\n")
		for j, doc := range docs {
			doc = strings.TrimSpace(doc)
			if doc == "" {
				continue
			}
			path := fmt.Sprintf("%s/policy-%d-%d.yaml", dir, i, j)
			if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
				t.Fatalf("write policy: %v", err)
			}
			paths = append(paths, path)
		}
	}
	pm := config.NewPolicyManager()
	if err := pm.LoadPolicies(paths); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	return pm
}

// EncryptedMPUPolicy returns a PolicyManager with a single policy that enables
// encrypted multipart uploads for buckets matching bucketGlob.
func EncryptedMPUPolicy(t *testing.T, bucketGlob string) *config.PolicyManager {
	t.Helper()
	return NewTestPolicyManager(t, fmt.Sprintf(`id: integration-mpu-encrypted
buckets:
  - "%s"
encrypt_multipart_uploads: true
`, bucketGlob))
}

// TestBucketPrefix returns a per-test bucket name prefix using the test name
// hash and current time, ensuring parallel tests don't collide.
func TestBucketPrefix(t *testing.T) string {
	t.Helper()
	h := fnv.New32a()
	_, _ = h.Write([]byte(t.Name()))
	return fmt.Sprintf("t%08x", h.Sum32())
}
