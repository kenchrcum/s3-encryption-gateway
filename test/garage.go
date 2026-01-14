package test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
)

// GarageTestServer manages a local Garage server for testing.
type GarageTestServer struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	DataDir   string
	ConfigDir string
	cmd       *exec.Cmd
	once      sync.Once
	cleanup   func()
	refCount  int
	refMutex  sync.Mutex
}

var (
	garageServer *GarageTestServer
	garageOnce   sync.Once
	garageError  error
)

// StartGarageServer starts a local Garage server for testing.
func StartGarageServer(t *testing.T) *GarageTestServer {
	t.Helper()

	garageOnce.Do(func() {
		// Ensure any previous garage instances are killed
		exec.Command("pkill", "garage").Run()
		time.Sleep(1 * time.Second)

		garageServer = &GarageTestServer{}

		t.Logf("Checking for garage binary...")
		if !hasGarageBinary() {
			t.Logf("Garage binary not found. Skipping Garage tests.")
			garageError = fmt.Errorf("garage binary not found")
			return
		}

		err := garageServer.startBinaryGarage(t)
		if err != nil {
			t.Logf("Failed to start Garage: %v", err)
			garageError = err
			return
		}
	})

	if garageError != nil {
		t.Skipf("Garage server setup failed: %v", garageError)
		return nil
	}

	return garageServer
}

func hasGarageBinary() bool {
	_, err := exec.LookPath("garage")
	return err == nil
}

func (s *GarageTestServer) startBinaryGarage(t *testing.T) error {
	// Create temp dirs
	tmpDir, err := os.MkdirTemp("", "garage-test-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	s.DataDir = filepath.Join(tmpDir, "data")
	s.ConfigDir = filepath.Join(tmpDir, "meta")
	os.MkdirAll(s.DataDir, 0755)
	os.MkdirAll(s.ConfigDir, 0755)

	// Create config.toml
	configFile := filepath.Join(tmpDir, "config.toml")
	configContent := fmt.Sprintf(`
metadata_dir = "%s"
data_dir = "%s"
db_engine = "sqlite"

rpc_bind_addr = "127.0.0.1:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret = "3fb5c4e9d0e2f8a1b7c6d5e4f3a2b1c03fb5c4e9d0e2f8a1b7c6d5e4f3a2b1c0"
replication_factor = 1

[s3_api]
s3_region = "garage"
api_bind_addr = "127.0.0.1:3900"
root_domain = ".s3.garage"

[s3_web]
bind_addr = "127.0.0.1:3902"
root_domain = ".web.garage"
index = "index.html"
`, s.ConfigDir, s.DataDir)

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	cmd := exec.Command("garage", "-c", configFile, "server")
	cmd.Stdout = os.Stdout // Debugging
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start garage server: %w", err)
	}
	s.cmd = cmd

	s.Endpoint = "http://127.0.0.1:3900"
	s.Bucket = fmt.Sprintf("test-bucket-%d", time.Now().UnixNano())

	// Wait for Garage to be ready (RPC)
	time.Sleep(10 * time.Second)

	// Check if process is still alive
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return fmt.Errorf("garage server exited unexpectedly")
	}

	// Configure Garage
	// 1. Get Node ID
	nodeIDCmd := exec.Command("garage", "-c", configFile, "node", "id")
	out, err := nodeIDCmd.CombinedOutput()
	if err != nil {
		s.StopForce()
		return fmt.Errorf("failed to get node id: %w, output: %s", err, string(out))
	}
	// Clean up node ID
	// Output format usually contains "Node ID: <ID>" or just the ID with some logs
	outputID := string(out)
	var nodeID string

	// Try to find "Node ID: <ID>"
	reNodeID := regexp.MustCompile(`Node ID:\s+([a-f0-9]+)`)
	match := reNodeID.FindStringSubmatch(outputID)
	if len(match) >= 2 {
		nodeID = match[1]
	} else {
		// Fallback: look for any 64-char hex string which looks like a node ID
		reHex := regexp.MustCompile(`[a-f0-9]{64}`)
		matchHex := reHex.FindString(outputID)
		if matchHex != "" {
			nodeID = matchHex
		} else {
			// Fallback to trimming
			nodeID = strings.TrimSpace(outputID)
		}
	}

	// 2. Assign Layout
	var layoutErr error
	for i := 0; i < 5; i++ {
		layoutCmd := exec.Command("garage", "-c", configFile, "layout", "assign", "-z", "dc1", "--capacity", "100M", nodeID)
		if out, err := layoutCmd.CombinedOutput(); err == nil {
			layoutErr = nil
			break
		} else {
			layoutErr = fmt.Errorf("failed to assign layout: %w, output: %s", err, string(out))
			time.Sleep(1 * time.Second)
		}
	}
	if layoutErr != nil {
		s.StopForce()
		// Determine if it failed because it's already assigned? Unlikely for new dir.
		return layoutErr
	}

	// 3. Apply Layout
	applyCmd := exec.Command("garage", "-c", configFile, "layout", "apply", "--version", "1")
	if out, err := applyCmd.CombinedOutput(); err != nil {
		s.StopForce()
		return fmt.Errorf("failed to apply layout: %w, output: %s", err, string(out))
	}

	// 4. Create Key
	keyName := "test-key"
	keyCmd := exec.Command("garage", "-c", configFile, "key", "create", keyName)
	out, err = keyCmd.CombinedOutput()
	if err != nil {
		s.StopForce()
		return fmt.Errorf("failed to create key: %w, output: %s", err, string(out))
	}
	// Parse Access/Secret from output
	// Output format:
	// Key name: test-key
	// Key ID: ...
	// Secret Key: ...
	outputStr := string(out)
	/* Example:
	Key name: test-key
	Key ID: GK...
	Secret Key: ...
	*/

	reAccess := regexp.MustCompile(`Key ID:\s+(\S+)`)
	reSecret := regexp.MustCompile(`(?i)Secret Key:\s+(\S+)`)

	accessMatch := reAccess.FindStringSubmatch(outputStr)
	secretMatch := reSecret.FindStringSubmatch(outputStr)

	if len(accessMatch) < 2 || len(secretMatch) < 2 {
		s.StopForce()
		return fmt.Errorf("failed to parse key from output: %s", outputStr)
	}
	s.AccessKey = accessMatch[1]
	s.SecretKey = secretMatch[1]

	// 5. Create Bucket and Allow Key
	// Garage bucket create automatically allows? No.
	// `garage bucket create <bucket>`
	// `garage bucket allow <bucket> --read --write --key <key>`

	bucketCmd := exec.Command("garage", "-c", configFile, "bucket", "create", s.Bucket)
	if out, err := bucketCmd.CombinedOutput(); err != nil {
		s.StopForce()
		return fmt.Errorf("failed to create bucket: %w, output: %s", err, string(out))
	}

	allowCmd := exec.Command("garage", "-c", configFile, "bucket", "allow", s.Bucket, "--read", "--write", "--key", keyName)
	if out, err := allowCmd.CombinedOutput(); err != nil {
		s.StopForce()
		return fmt.Errorf("failed to allow key: %w, output: %s", err, string(out))
	}

	s.cleanup = func() {
		if s.cmd != nil && s.cmd.Process != nil {
			s.cmd.Process.Kill()
		}
		os.RemoveAll(tmpDir)
	}

	return nil
}

// StopForce forcibly stops the Garage server.
func (s *GarageTestServer) StopForce() {
	s.once.Do(func() {
		if s.cleanup != nil {
			s.cleanup()
		}
	})
}

// Stop represents cleanup for test runner.
func (s *GarageTestServer) Stop() {
	// No-op for shared server
}

// GetGatewayConfig returns gateway configuration for testing.
func (s *GarageTestServer) GetGatewayConfig() *config.Config {
	return &config.Config{
		ListenAddr: "127.0.0.1:0", // Use random available port on loopback
		LogLevel:   "info",
		Backend: config.BackendConfig{
			Endpoint:  s.Endpoint,
			Region:    "garage",
			AccessKey: s.AccessKey,
			SecretKey: s.SecretKey,
			Provider:  "s3", // Generic S3 or maybe "garage" if supported? Let's use generic s3 for now or check if there is specific provider logic.
			// Actually MinIO uses "minio". Garage should likely use "s3" or "minio" (compatible).
			// Let's use "s3" generic.
			UseSSL:       false,
			UsePathStyle: true, // Garage supports path style
		},
		Encryption: config.EncryptionConfig{
			Password: "test-encryption-password-123456",
		},
		Compression: config.CompressionConfig{
			Enabled: false,
		},
	}
}
