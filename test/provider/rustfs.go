package provider

// RustFS provider for the conformance test suite.
//
// RustFS is a Rust-based S3-compatible object storage server.
// Image: rustfs/rustfs:latest (Docker Hub)
//
// WARNING: RustFS is currently in active development and explicitly labelled
// "Do NOT use in production" by its authors. We test against it to catch
// regressions early and to help the project improve.  The capability bitmap
// is conservative; expand it as the implementation matures.
//
// Skip env var: GATEWAY_TEST_SKIP_RUSTFS=1

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func init() {
	if os.Getenv("GATEWAY_TEST_SKIP_RUSTFS") == "" {
		Register(&rustfsProvider{})
	}
}

type rustfsProvider struct{}

func (p *rustfsProvider) Name() string { return "rustfs" }

// Capabilities returns a conservative bitmap reflecting RustFS's current
// known-working feature set.  RustFS uses the same health and credential
// conventions as MinIO, so basic CRUD + multipart + tagging work; however
// several advanced features (Object Lock, conditional writes, versioning) are
// not yet fully tested or documented upstream.
//
// Expand this bitmap as conformance tests confirm additional features pass.
func (p *rustfsProvider) Capabilities() Capabilities {
	return CapMultipartUpload |
		CapMultipartCopy |
		CapObjectTagging |
		CapInlinePutTagging |
		CapPresignedURL |
		CapBatchDelete |
		CapEncryptedMPU |
		CapLoadTest
}

func (p *rustfsProvider) CleanupPolicy() CleanupPolicy { return CleanupPolicyDelete }

func (p *rustfsProvider) BackendConfig(inst Instance) config.BackendConfig {
	return config.BackendConfig{
		Endpoint:     inst.Endpoint,
		Region:       inst.Region,
		AccessKey:    inst.AccessKey,
		SecretKey:    inst.SecretKey,
		Provider:     "s3",
		UseSSL:       false,
		UsePathStyle: true,
	}
}

func (p *rustfsProvider) Start(ctx context.Context, t *testing.T) Instance {
	t.Helper()

	const (
		s3Port      = "9000/tcp"
		consolePort = "9001/tcp"
		accessKey   = "rustfsadmin"
		secretKey   = "rustfsadmin"
	)

	req := tc.ContainerRequest{
		Image:        "rustfs/rustfs:latest",
		ExposedPorts: []string{s3Port, consolePort},
		Env: map[string]string{
			"RUSTFS_ACCESS_KEY": accessKey,
			"RUSTFS_SECRET_KEY": secretKey,
		},
		// Positional argument: data directory.  tmpfs mount eliminates the
		// host chown requirement (RustFS runs as UID 10001).
		Cmd: []string{
			"--access-key", accessKey,
			"--secret-key", secretKey,
			"/data",
		},
		Mounts: tc.ContainerMounts{
			{
				// Anonymous tmpfs — no host path, no ownership friction.
				Source: tc.GenericTmpfsMountSource{},
				Target: "/data",
			},
		},
		// RustFS exposes the same MinIO health endpoint path.
		WaitingFor: wait.ForHTTP("/minio/health/live").
			WithPort(s3Port).
			WithStatusCodeMatcher(func(status int) bool { return status == http.StatusOK }).
			WithStartupTimeout(90 * time.Second),
	}

	c, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("rustfs provider: failed to start container (Docker unavailable?): %v", err)
		return Instance{}
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("rustfs provider: host: %v", err)
	}
	s3Mapped, err := c.MappedPort(ctx, s3Port)
	if err != nil {
		t.Fatalf("rustfs provider: s3 port: %v", err)
	}

	bucket := fmt.Sprintf("conf-%s-%d", p.Name(), time.Now().UnixNano())
	inst := Instance{
		Endpoint:     fmt.Sprintf("http://%s:%s", host, s3Mapped.Port()),
		Region:       "us-east-1",
		AccessKey:    accessKey,
		SecretKey:    secretKey,
		Bucket:       bucket,
		ProviderName: p.Name(),
	}
	createBucketS3(ctx, t, inst)
	return inst
}
