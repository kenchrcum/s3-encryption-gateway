package test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/s3"
)

// MinIOTestServer manages a local MinIO server for testing.
type MinIOTestServer struct {
	Endpoint   string
	AccessKey  string
	SecretKey  string
	Bucket     string
	DataDir    string
	cmd        *exec.Cmd
	once       sync.Once
	cleanup    func()
	refCount   int
	refMutex   sync.Mutex
}

var (
	minioServer *MinIOTestServer
	minioOnce   sync.Once
	minioError  error
)

// StartMinIOServer starts a local MinIO server for testing.
// It uses Docker if available, otherwise tries to use a local MinIO binary.
// This uses a global instance shared across integration tests.
func StartMinIOServer(t *testing.T) *MinIOTestServer {
	t.Helper()

	minioOnce.Do(func() {
		// Use environment variables for MinIO credentials
		accessKey := os.Getenv("MINIO_ROOT_USER")
		if accessKey == "" {
			accessKey = "minioadmin"
		}
		secretKey := os.Getenv("MINIO_ROOT_PASSWORD")
		if secretKey == "" {
			secretKey = "minioadmin"
		}

		// Use unique bucket name per test run
		bucketName := fmt.Sprintf("test-bucket-%d", time.Now().UnixNano())

		server := &MinIOTestServer{
			AccessKey: accessKey,
			SecretKey: secretKey,
			Bucket:    bucketName,
		}

		// Try Docker first, then fallback to MinIO binary
		var err error
		t.Logf("Testing Docker availability...")
		if hasDocker() {
			t.Logf("Docker is available, trying Docker MinIO...")
			err = server.startDockerMinIO(t)
			if err != nil {
				t.Logf("Docker MinIO failed: %v", err)
			}
		} else {
			t.Logf("Docker not available")
		}

		// If Docker failed or is not available, try MinIO binary
		if err != nil || !hasDocker() {
			t.Logf("Testing MinIO binary availability...")
			if hasMinIOBinary() {
				t.Logf("MinIO binary available, trying binary MinIO...")
				err = server.startBinaryMinIO(t)
				if err != nil {
					t.Logf("Binary MinIO failed: %v", err)
					minioError = err
					return
				}
				t.Logf("Binary MinIO started successfully")
			} else {
				t.Logf("MinIO binary not available")
				if hasDocker() {
					minioError = fmt.Errorf("MinIO server setup failed: Docker networking issues and no MinIO binary available. Original error: %w", err)
				} else {
					minioError = fmt.Errorf("MinIO server not available. Install Docker or MinIO binary for integration tests")
				}
				return
			}
		}

		minioServer = server
	})

	if minioError != nil {
		t.Skipf("MinIO server setup failed: %v", minioError)
		return nil
	}

	// Increment reference count
	minioServer.refMutex.Lock()
	minioServer.refCount++
	minioServer.refMutex.Unlock()

	return minioServer
}

// StartMinIOServerForProvider starts a separate MinIO server instance for provider tests.
// This doesn't use the global instance, allowing provider tests to run independently.
func StartMinIOServerForProvider(t *testing.T) *MinIOTestServer {
	t.Helper()

	// Use environment variables for MinIO credentials
	accessKey := os.Getenv("MINIO_ROOT_USER")
	if accessKey == "" {
		accessKey = "minioadmin"
	}
	secretKey := os.Getenv("MINIO_ROOT_PASSWORD")
	if secretKey == "" {
		secretKey = "minioadmin"
	}

	// Use unique bucket name per test run
	bucketName := fmt.Sprintf("test-bucket-%d", time.Now().UnixNano())

	server := &MinIOTestServer{
		AccessKey: accessKey,
		SecretKey: secretKey,
		Bucket:    bucketName,
	}

	// Try Docker first, then fallback to MinIO binary
	var err error
	t.Logf("Testing Docker availability...")
	if hasDocker() {
		t.Logf("Docker is available, trying Docker MinIO...")
		err = server.startDockerMinIO(t)
		if err != nil {
			t.Logf("Docker MinIO failed: %v", err)
		} else {
			t.Logf("Docker MinIO started successfully")
			return server
		}
	} else {
		t.Logf("Docker not available")
	}

	// If Docker failed or is not available, try MinIO binary
	if err != nil || !hasDocker() {
		t.Logf("Testing MinIO binary availability...")
		if hasMinIOBinary() {
			t.Logf("MinIO binary available, trying binary MinIO...")
			err = server.startBinaryMinIO(t)
			if err != nil {
				t.Logf("Binary MinIO failed: %v", err)
			} else {
				t.Logf("Binary MinIO started successfully")
				return server
			}
		} else {
			t.Logf("MinIO binary not available")
		}
	}

	t.Skipf("MinIO server setup failed: %v", err)
	return nil
}

// hasDocker checks if Docker is available.
func hasDocker() bool {
	cmd := exec.Command("docker", "version")
	return cmd.Run() == nil
}

// hasDockerCompose checks if docker-compose is available.
func hasDockerCompose() bool {
	cmd := exec.Command("docker-compose", "version")
	return cmd.Run() == nil
}

// hasMinIOBinary checks if MinIO binary is available in PATH.
func hasMinIOBinary() bool {
	cmd := exec.Command("minio", "--version")
	return cmd.Run() == nil
}

// startDockerMinIO starts MinIO using Docker.
func (m *MinIOTestServer) startDockerMinIO(t *testing.T) error {
	t.Helper()

	// Try docker-compose first (if docker-compose.yml exists)
	// Try multiple paths
	dockerComposePaths := []string{
		"test/docker-compose.yml",
		"./test/docker-compose.yml",
	}
	var dockerComposePath string
	for _, path := range dockerComposePaths {
		if _, err := os.Stat(path); err == nil {
			dockerComposePath = path
			break
		}
	}
	
	if dockerComposePath != "" {
		// Use docker-compose if available
		var cmd *exec.Cmd
		if hasDockerCompose() {
			cmd = exec.Command("docker-compose", "-f", dockerComposePath, "up", "-d")
		} else if hasDocker() {
			// Try "docker compose" (newer syntax)
			cmd = exec.Command("docker", "compose", "-f", dockerComposePath, "up", "-d")
		}
		
		if cmd != nil {
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to start MinIO Docker container: %w", err)
			}

			// Wait a bit for MinIO to start
			time.Sleep(3 * time.Second)
			m.Endpoint = "http://localhost:9000"

			// Verify MinIO is running
			if err := m.waitForMinIO(); err != nil {
				var downCmd *exec.Cmd
				if hasDockerCompose() {
					downCmd = exec.Command("docker-compose", "-f", dockerComposePath, "down")
				} else {
					downCmd = exec.Command("docker", "compose", "-f", dockerComposePath, "down")
				}
				downCmd.Run()
				return fmt.Errorf("MinIO failed to start: %w", err)
			}

			var cleanupCmd *exec.Cmd
			if hasDockerCompose() {
				cleanupCmd = exec.Command("docker-compose", "-f", dockerComposePath, "down", "-v")
			} else {
				cleanupCmd = exec.Command("docker", "compose", "-f", dockerComposePath, "down", "-v")
			}
			m.cleanup = func() {
				cleanupCmd.Run()
			}
			return nil
		}
	}

	// Fallback: Start MinIO container directly
	containerName := fmt.Sprintf("minio-test-%d", time.Now().Unix())
	port := "9000"
	m.Endpoint = fmt.Sprintf("http://localhost:%s", port)

	// Start MinIO in Docker
	// Use environment variables if set, otherwise use the configured values
	minioUser := os.Getenv("MINIO_ROOT_USER")
	if minioUser == "" {
		minioUser = m.AccessKey
	}
	minioPassword := os.Getenv("MINIO_ROOT_PASSWORD")
	if minioPassword == "" {
		minioPassword = m.SecretKey
	}

	cmd := exec.Command("docker", "run", "--rm", "-d",
		"-p", fmt.Sprintf("%s:9000", port),
		"-p", "9001:9001",
		"-e", fmt.Sprintf("MINIO_ROOT_USER=%s", minioUser),
		"-e", fmt.Sprintf("MINIO_ROOT_PASSWORD=%s", minioPassword),
		"-e", "MINIO_API_BUCKET_AUTO_CREATION=on",
		"-e", "MINIO_API_ROOT_ACCESS=on",
		"--name", containerName,
		"minio/minio:latest",
		"server", "/data", "--console-address", ":9001",
	)

	if err := cmd.Run(); err != nil {
		// Clean up any partially created container
		exec.Command("docker", "rm", "-f", containerName).Run()
		return fmt.Errorf("failed to start MinIO Docker container: %w", err)
	}

	time.Sleep(3 * time.Second) // Wait for MinIO to start

	// Verify MinIO is running
	if err := m.waitForMinIO(); err != nil {
		exec.Command("docker", "stop", containerName).Run()
		return fmt.Errorf("MinIO failed to start: %w", err)
	}

	// Create test bucket
	if err := m.createBucket(); err != nil {
		exec.Command("docker", "stop", containerName).Run()
		t.Logf("Bucket creation note: %v (bucket will be created on first put)", err)
	}

	m.cleanup = func() {
		exec.Command("docker", "stop", containerName).Run()
	}
	return nil
}

// startBinaryMinIO starts MinIO using local binary.
func (m *MinIOTestServer) startBinaryMinIO(t *testing.T) error {
	t.Helper()

	// Create temporary data directory
	dataDir, err := os.MkdirTemp("", "minio-test-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	m.DataDir = dataDir

	port := "9000"
	m.Endpoint = fmt.Sprintf("http://localhost:%s", port)

	// Start MinIO server
	cmd := exec.Command("minio", "server", dataDir,
		"--address", fmt.Sprintf(":%s", port),
		"--console-address", ":9001",
	)
	cmd.Env = os.Environ()
	// Use environment variables if set, otherwise use the configured values
	minioUser := os.Getenv("MINIO_ROOT_USER")
	if minioUser == "" {
		minioUser = m.AccessKey
	}
	minioPassword := os.Getenv("MINIO_ROOT_PASSWORD")
	if minioPassword == "" {
		minioPassword = m.SecretKey
	}
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("MINIO_ROOT_USER=%s", minioUser),
		fmt.Sprintf("MINIO_ROOT_PASSWORD=%s", minioPassword),
		"MINIO_API_BUCKET_AUTO_CREATION=on", // Allow automatic bucket creation
		"MINIO_API_ROOT_ACCESS=on", // Allow root access
	)

	if err := cmd.Start(); err != nil {
		os.RemoveAll(dataDir)
		return fmt.Errorf("failed to start MinIO: %w", err)
	}

	m.cmd = cmd
	time.Sleep(2 * time.Second)

	// Verify MinIO is running
	if err := m.waitForMinIO(); err != nil {
		m.Stop()
		return fmt.Errorf("MinIO failed to start: %w", err)
	}

	// Create test bucket
	if err := m.createBucket(); err != nil {
		m.Stop()
		return fmt.Errorf("failed to create test bucket: %w", err)
	}

	m.cleanup = func() {
		if m.cmd != nil && m.cmd.Process != nil {
			m.cmd.Process.Kill()
		}
		os.RemoveAll(dataDir)
	}
	return nil
}

// waitForMinIO waits for MinIO to be ready.
func (m *MinIOTestServer) waitForMinIO() error {
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for MinIO")
		case <-ticker.C:
			resp, err := http.Get(m.Endpoint + "/minio/health/live")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
	}
}

// createBucket creates the test bucket in MinIO.
func (m *MinIOTestServer) createBucket() error {
	// Wait for MinIO to be ready
	time.Sleep(2 * time.Second)

	// Try to create bucket using AWS CLI
	return m.createBucketViaAWSCLI()
}

// createBucketViaAWSCLI creates the bucket using AWS CLI.
func (m *MinIOTestServer) createBucketViaAWSCLI() error {
	// Configure AWS CLI for MinIO
	cmd := exec.Command("aws", "configure", "set", "aws_access_key_id", m.AccessKey)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure AWS CLI access key: %w", err)
	}

	cmd = exec.Command("aws", "configure", "set", "aws_secret_access_key", m.SecretKey)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure AWS CLI secret key: %w", err)
	}

	cmd = exec.Command("aws", "configure", "set", "region", "us-east-1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure AWS CLI region: %w", err)
	}

	// Try to create bucket using AWS CLI with retries
	for attempts := 0; attempts < 5; attempts++ {
		cmd = exec.Command("aws", "s3", "mb", fmt.Sprintf("s3://%s", m.Bucket),
			"--endpoint-url", m.Endpoint,
			"--no-verify-ssl")
		output, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}

		outputStr := string(output)
		if strings.Contains(outputStr, "SlowDownWrite") {
			// Wait before retrying
			time.Sleep(time.Duration(attempts+1) * time.Second)
			continue
		}

		return fmt.Errorf("failed to create bucket with AWS CLI: %w, output: %s", err, outputStr)
	}

	return fmt.Errorf("failed to create bucket after retries")
}

// createBucketViaSDK creates the test bucket using AWS SDK (fallback method).
func (m *MinIOTestServer) createBucketViaSDK() error {
	cfg := &config.BackendConfig{
		Endpoint:  m.Endpoint,
		Region:    "us-east-1",
		AccessKey: m.AccessKey,
		SecretKey: m.SecretKey,
		Provider:  "minio",
		UseSSL:    false,
	}

	client, err := s3.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create S3 client: %w", err)
	}

	// Try to create bucket explicitly by putting a dummy object
	// MinIO should create buckets implicitly on first PUT
	testKey := ".bucket-init"
	ctx := context.Background()
	emptyReader := bytes.NewReader([]byte{})

	// Try multiple times in case MinIO needs a moment to be ready
	for attempts := 0; attempts < 5; attempts++ {
		err = client.PutObject(ctx, m.Bucket, testKey, emptyReader, nil, nil)
		if err == nil {
			fmt.Printf("Successfully created bucket %s via SDK\n", m.Bucket)
			return nil
		}
		fmt.Printf("Attempt %d: Failed to create bucket %s: %v\n", attempts+1, m.Bucket, err)
		time.Sleep(time.Duration(attempts+1) * time.Second)
	}

	// Don't fail - bucket will be created on first real PUT from the test
	fmt.Printf("Warning: Could not pre-create test bucket %s after retries, proceeding anyway\n", m.Bucket)
	return nil
}

// Stop stops the MinIO server and cleans up resources.
// Note: For integration tests, we don't actually stop the server to allow
// multiple tests to share the same instance. Use StopForce() for explicit cleanup.
func (m *MinIOTestServer) Stop() {
	// Don't actually stop - let tests share the server
	// This is a no-op to prevent premature server shutdown
}

// StopForce forcibly stops the MinIO server.
func (m *MinIOTestServer) StopForce() {
	m.once.Do(func() {
		if m.cleanup != nil {
			m.cleanup()
		}
	})
}

// GetS3Client returns a configured S3 client for the test server.
func (m *MinIOTestServer) GetS3Client() (s3.Client, error) {
	cfg := &config.BackendConfig{
		Endpoint:  m.Endpoint,
		Region:    "us-east-1",
		AccessKey: m.AccessKey,
		SecretKey: m.SecretKey,
		Provider:  "minio",
		UseSSL:    false,
	}

	return s3.NewClient(cfg)
}

// GetGatewayConfig returns gateway configuration for testing.
func (m *MinIOTestServer) GetGatewayConfig() *config.Config {
	return &config.Config{
		ListenAddr: ":18080", // Use different port to avoid conflicts
		LogLevel:   "info",
		Backend: config.BackendConfig{
			Endpoint:  m.Endpoint,
			Region:    "us-east-1",
			AccessKey: m.AccessKey,
			SecretKey: m.SecretKey,
			Provider:  "minio",
			UseSSL:    false,
		},
		Encryption: config.EncryptionConfig{
			Password: "test-encryption-password-123456",
		},
		Compression: config.CompressionConfig{
			Enabled: false,
		},
	}
}
