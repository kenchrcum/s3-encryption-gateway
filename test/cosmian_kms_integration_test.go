//go:build integration
// +build integration

package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/kenneth/s3-encryption-gateway/internal/api"
	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/kenneth/s3-encryption-gateway/internal/metrics"
	"github.com/kenneth/s3-encryption-gateway/internal/middleware"
	"github.com/kenneth/s3-encryption-gateway/internal/s3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// TestCosmianKMSIntegration tests the full integration with a real Cosmian KMS instance.
// This test requires Docker to be running and will start a Cosmian KMS container.
func TestCosmianKMSIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if Docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker not available, skipping integration test")
	}

	// Start Cosmian KMS container with KMIP enabled
	_, kmsEndpoint, tlsCfg, cleanup, containerName, _ := startCosmianKMS(t)
	defer cleanup()

	// Wait for KMS to be ready
	waitForKMSReady(t, kmsEndpoint, containerName)

	// Create a wrapping key in Cosmian KMS via KMIP
	keyID := createWrappingKey(t, kmsEndpoint)

	// Create KMS manager
	manager, err := crypto.NewCosmianKMIPManager(crypto.CosmianKMIPOptions{
		Endpoint: kmsEndpoint,
		Keys: []crypto.KMIPKeyReference{
			{ID: keyID, Version: 1},
		},
		TLSConfig:      tlsCfg,
		Timeout:        10 * time.Second,
		Provider:       "cosmian",
		DualReadWindow: 1,
	})
	require.NoError(t, err)
	defer func() {
		_ = manager.Close(context.Background())
	}()

	// Create encryption engine with KMS
	engine, err := crypto.NewEngine("fallback-password-123456")
	require.NoError(t, err)
	crypto.SetKeyManager(engine, manager)

	// Test 1: Basic encryption/decryption
	t.Run("BasicEncryption", func(t *testing.T) {
		plaintext := []byte("Hello, Cosmian KMS Integration Test!")
		metadata := map[string]string{
			"Content-Type": "text/plain",
		}

		// Encrypt
		encReader, encMetadata, err := engine.Encrypt(bytes.NewReader(plaintext), metadata)
		require.NoError(t, err)
		require.Equal(t, "true", encMetadata[crypto.MetaEncrypted])
		require.NotEmpty(t, encMetadata[crypto.MetaWrappedKeyCiphertext])
		require.Equal(t, "cosmian", encMetadata[crypto.MetaKMSProvider])
		require.NotEmpty(t, encMetadata[crypto.MetaKMSKeyID])

		// Decrypt
		decReader, decMetadata, err := engine.Decrypt(encReader, encMetadata)
		require.NoError(t, err)
		require.Equal(t, "text/plain", decMetadata["Content-Type"])

		decrypted, err := io.ReadAll(decReader)
		require.NoError(t, err)
		require.Equal(t, plaintext, decrypted)
	})

	// Test 2: Large file encryption
	t.Run("LargeFileEncryption", func(t *testing.T) {
		// Generate 1MB of test data
		largeData := make([]byte, 1024*1024)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		metadata := map[string]string{
			"Content-Type": "application/octet-stream",
		}

		// Encrypt
		encReader, encMetadata, err := engine.Encrypt(bytes.NewReader(largeData), metadata)
		require.NoError(t, err)
		require.Equal(t, "true", encMetadata[crypto.MetaEncrypted])

		// Decrypt
		decReader, _, err := engine.Decrypt(encReader, encMetadata)
		require.NoError(t, err)

		decrypted, err := io.ReadAll(decReader)
		require.NoError(t, err)
		require.Equal(t, largeData, decrypted)
	})

	// Test 3: Multiple objects with same key
	t.Run("MultipleObjects", func(t *testing.T) {
		testData := [][]byte{
			[]byte("Object 1"),
			[]byte("Object 2"),
			[]byte("Object 3"),
		}

		var encryptedData [][]byte
		var encryptedMetadata []map[string]string

		// Encrypt multiple objects
		for i, data := range testData {
			encReader, encMetadata, err := engine.Encrypt(bytes.NewReader(data), map[string]string{
				"Content-Type": "text/plain",
			})
			require.NoError(t, err, "Failed to encrypt object %d", i+1)

			encData, err := io.ReadAll(encReader)
			require.NoError(t, err)
			encryptedData = append(encryptedData, encData)
			encryptedMetadata = append(encryptedMetadata, encMetadata)
		}

		// Decrypt all objects
		for i, encData := range encryptedData {
			decReader, _, err := engine.Decrypt(bytes.NewReader(encData), encryptedMetadata[i])
			require.NoError(t, err, "Failed to decrypt object %d", i+1)

			decrypted, err := io.ReadAll(decReader)
			require.NoError(t, err)
			require.Equal(t, testData[i], decrypted, "Object %d decryption mismatch", i+1)
		}
	})

	// Test 4: Chunked encryption mode
	t.Run("ChunkedEncryption", func(t *testing.T) {
		chunkedEngine, err := crypto.NewEngineWithChunking(
			"fallback-password-123456",
			nil,
			"",
			nil,
			true,
			64*1024, // 64KB chunks
		)
		require.NoError(t, err)
		crypto.SetKeyManager(chunkedEngine, manager)

		// Generate test data larger than chunk size
		testData := make([]byte, 200*1024) // 200KB
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		encReader, encMetadata, err := chunkedEngine.Encrypt(bytes.NewReader(testData), map[string]string{
			"Content-Type": "application/octet-stream",
		})
		require.NoError(t, err)
		require.Equal(t, "true", encMetadata[crypto.MetaEncrypted])
		require.Equal(t, "true", encMetadata[crypto.MetaChunkedFormat])

		decReader, _, err := chunkedEngine.Decrypt(encReader, encMetadata)
		require.NoError(t, err)

		decrypted, err := io.ReadAll(decReader)
		require.NoError(t, err)
		require.Equal(t, testData, decrypted)
	})
}

// TestCosmianKMSKeyRotation tests key rotation with dual-read window support.
func TestCosmianKMSKeyRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker not available, skipping integration test")
	}

	// Start Cosmian KMS container with KMIP enabled
	_, kmsEndpoint, tlsCfg, cleanup, containerName, _ := startCosmianKMS(t)
	defer cleanup()

	waitForKMSReady(t, kmsEndpoint, containerName)

	// Create initial wrapping key
	keyID1 := createWrappingKey(t, kmsEndpoint)

	// Create second wrapping key for rotation
	keyID2 := createWrappingKey(t, kmsEndpoint)

	// Create manager with both keys (dual-read window)
	manager, err := crypto.NewCosmianKMIPManager(crypto.CosmianKMIPOptions{
		Endpoint: kmsEndpoint,
		Keys: []crypto.KMIPKeyReference{
			{ID: keyID1, Version: 1},
			{ID: keyID2, Version: 2},
		},
		TLSConfig:      tlsCfg,
		Timeout:        10 * time.Second,
		Provider:       "cosmian",
		DualReadWindow: 2, // Allow reading with previous 2 versions
	})
	require.NoError(t, err)
	defer func() {
		_ = manager.Close(context.Background())
	}()

	engine, err := crypto.NewEngine("fallback-password-123456")
	require.NoError(t, err)
	crypto.SetKeyManager(engine, manager)

	// Encrypt with key version 1
	plaintext1 := []byte("Encrypted with key version 1")
	encReader1, encMetadata1, err := engine.Encrypt(bytes.NewReader(plaintext1), map[string]string{
		"Content-Type": "text/plain",
	})
	require.NoError(t, err)
	require.Equal(t, "1", encMetadata1[crypto.MetaKeyVersion])

	// Store encrypted data as bytes for later use (reader gets consumed)
	encryptedData1, err := io.ReadAll(encReader1)
	require.NoError(t, err)

	// Decrypt object encrypted with version 1
	decReader1, _, err := engine.Decrypt(bytes.NewReader(encryptedData1), encMetadata1)
	require.NoError(t, err)
	decrypted1, err := io.ReadAll(decReader1)
	require.NoError(t, err)
	require.Equal(t, plaintext1, decrypted1)

	// Force encryption with key version 2 by creating new manager with version 2 as primary
	manager2, err := crypto.NewCosmianKMIPManager(crypto.CosmianKMIPOptions{
		Endpoint: kmsEndpoint,
		Keys: []crypto.KMIPKeyReference{
			{ID: keyID2, Version: 2}, // Version 2 as primary
			{ID: keyID1, Version: 1}, // Version 1 for backward compatibility
		},
		TLSConfig:      tlsCfg,
		Timeout:        10 * time.Second,
		Provider:       "cosmian",
		DualReadWindow: 2,
	})
	require.NoError(t, err)
	defer func() {
		_ = manager2.Close(context.Background())
	}()

	engine2, err := crypto.NewEngine("fallback-password-123456")
	require.NoError(t, err)
	crypto.SetKeyManager(engine2, manager2)

	// Encrypt with key version 2
	plaintext2 := []byte("Encrypted with key version 2")
	encReader2, encMetadata2, err := engine2.Encrypt(bytes.NewReader(plaintext2), map[string]string{
		"Content-Type": "text/plain",
	})
	require.NoError(t, err)
	require.Equal(t, "2", encMetadata2[crypto.MetaKeyVersion])

	// Decrypt object encrypted with version 2
	decReader2, _, err := engine2.Decrypt(encReader2, encMetadata2)
	require.NoError(t, err)
	decrypted2, err := io.ReadAll(decReader2)
	require.NoError(t, err)
	require.Equal(t, plaintext2, decrypted2)

	// Verify dual-read: decrypt version 1 object with version 2 manager
	decReader1v2, _, err := engine2.Decrypt(bytes.NewReader(encryptedData1), encMetadata1)
	require.NoError(t, err, "Dual-read window should allow decrypting with previous key version")
	decrypted1v2, err := io.ReadAll(decReader1v2)
	require.NoError(t, err)
	require.Equal(t, plaintext1, decrypted1v2)
}

// generateTestCertificates generates self-signed certificates for Cosmian KMS KMIP testing.
// Returns paths to PKCS#12 file, CA certificate file, and client certificate/key for mutual TLS.
func generateTestCertificates(t *testing.T) (p12Path, caCertPath, clientCertPath, clientKeyPath string) {
	t.Helper()

	t.Log("Generating test certificates...")

	// Create temporary directory for certificates
	tmpDir := t.TempDir()

	// Generate CA private key (use smaller key size for faster generation in tests)
	t.Log("Generating CA private key...")
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	t.Log("CA private key generated")

	// Create CA certificate
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	// Write CA certificate to file
	caCertPath = filepath.Join(tmpDir, "ca-cert.pem")
	caCertFile, err := os.Create(caCertPath)
	require.NoError(t, err)
	defer caCertFile.Close()

	err = pem.Encode(caCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	require.NoError(t, err)

	// Generate server private key (use smaller key size for faster generation in tests)
	t.Log("Generating server private key...")
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	t.Log("Server private key generated")

	// Create server certificate
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Server"},
			Country:      []string{"US"},
			CommonName:   "localhost",
			SerialNumber: "1",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	// Create PKCS#12 file using OpenSSL to avoid RC2-40-CBC (not supported in OpenSSL 3.x)
	// Write temporary PEM files
	keyPEMPath := filepath.Join(tmpDir, "server-key.pem")
	certPEMPath := filepath.Join(tmpDir, "server-cert.pem")

	// Write private key to PEM
	keyPEMFile, err := os.Create(keyPEMPath)
	require.NoError(t, err)
	err = pem.Encode(keyPEMFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	require.NoError(t, err)
	keyPEMFile.Close()

	// Write certificate to PEM
	certPEMFile, err := os.Create(certPEMPath)
	require.NoError(t, err)
	err = pem.Encode(certPEMFile, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	require.NoError(t, err)
	certPEMFile.Close()

	// Use OpenSSL to create PKCS#12 with AES-256-CBC (supported in OpenSSL 3.x)
	// Must explicitly specify encryption algorithm to avoid RC2-40-CBC
	p12Path = filepath.Join(tmpDir, "server.p12")
	opensslCmd := exec.Command("openssl", "pkcs12", "-export",
		"-inkey", keyPEMPath,
		"-in", certPEMPath,
		"-out", p12Path,
		"-passout", "pass:test-password",
		"-legacy",                 // Enable legacy algorithms for reading
		"-certpbe", "AES-256-CBC", // Certificate encryption algorithm
		"-keypbe", "AES-256-CBC", // Key encryption algorithm
		"-macalg", "sha256", // MAC algorithm
	)
	output, err := opensslCmd.CombinedOutput()
	if err != nil {
		// Try without -legacy flag but with explicit algorithms
		opensslCmd = exec.Command("openssl", "pkcs12", "-export",
			"-inkey", keyPEMPath,
			"-in", certPEMPath,
			"-out", p12Path,
			"-passout", "pass:test-password",
			"-certpbe", "AES-256-CBC",
			"-keypbe", "AES-256-CBC",
			"-macalg", "sha256",
		)
		output, err = opensslCmd.CombinedOutput()
	}
	require.NoError(t, err, "Failed to create PKCS#12 file with OpenSSL: %s", string(output))

	// Clean up temporary PEM files
	os.Remove(keyPEMPath)
	os.Remove(certPEMPath)

	// Generate client certificate for mutual TLS authentication
	t.Log("Generating client certificate...")
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
			Country:      []string{"US"},
			CommonName:   "kmip-client",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	// Write client certificate and key
	clientCertPath = filepath.Join(tmpDir, "client-cert.pem")
	clientCertFile, err := os.Create(clientCertPath)
	require.NoError(t, err)
	err = pem.Encode(clientCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	require.NoError(t, err)
	clientCertFile.Close()

	clientKeyPath = filepath.Join(tmpDir, "client-key.pem")
	clientKeyFile, err := os.Create(clientKeyPath)
	require.NoError(t, err)
	err = pem.Encode(clientKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})
	require.NoError(t, err)
	clientKeyFile.Close()

	t.Logf("Certificates generated: p12=%s, ca=%s, client-cert=%s, client-key=%s", p12Path, caCertPath, clientCertPath, clientKeyPath)
	return p12Path, caCertPath, clientCertPath, clientKeyPath
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// startCosmianKMS starts a Cosmian KMS Docker container with KMIP enabled and returns container info and endpoint.
func startCosmianKMS(t *testing.T) (containerID string, endpoint string, tlsCfg *tls.Config, cleanup func(), containerName string, caCertPath string) {
	t.Helper()

	// Check if Docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("Docker is not available in PATH. Integration tests require Docker.")
	}

	t.Log("Starting Cosmian KMS container setup...")

	// Start a plain Docker container without TLS configuration
	// This matches the user's working example: docker run --rm -d -p 5696:5696 -p 9998:9998 ghcr.io/cosmian/kms:5.14.1 server
	// The CLI can connect to this without certificate issues

	// For KMIP client, we'll use a basic TLS config that accepts the default certificates
	// or skip verification for testing
	tlsCfg = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // Accept self-signed certificates for testing
	}

	// No CA cert path needed for plain container
	caCertPath = ""

	// Generate unique container name
	containerName = fmt.Sprintf("cosmian-kms-test-%d", time.Now().UnixNano())
	t.Logf("Starting container: %s", containerName)

	// Start plain Cosmian KMS container (no TLS configuration)
	// This matches: docker run --rm -d -p 5696:5696 -p 9998:9998 ghcr.io/cosmian/kms:5.14.1 server
	t.Log("Executing docker run command...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start plain container without TLS configuration
	cmd := exec.CommandContext(ctx, "docker", "run", "-d",
		"--name", containerName,
		"-p", "5696:5696", // KMIP port
		"-p", "9998:9998", // REST API port
		"--rm",
		"ghcr.io/cosmian/kms:5.14.1",
		"server",
	)
	t.Logf("Docker command: docker run -d --name %s -p 5696:5696 -p 9998:9998 --rm ghcr.io/cosmian/kms:5.14.1 server", containerName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Docker command output: %s", string(output))
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatal("Docker command timed out after 30 seconds")
		}
	}
	require.NoError(t, err, "Failed to start Cosmian KMS container: %s", string(output))
	containerID = strings.TrimSpace(string(output))
	t.Logf("Container started with ID: %s", containerID)

	// Immediately check container status and logs
	t.Log("Checking initial container status...")
	statusCmd := exec.Command("docker", "inspect", "-f", "{{.State.Status}}", containerName)
	statusOutput, _ := statusCmd.CombinedOutput()
	t.Logf("Container status: %s", strings.TrimSpace(string(statusOutput)))

	// Get logs immediately to see if there are startup errors
	// Wait a moment for container to initialize
	time.Sleep(1 * time.Second)
	logsCmd := exec.Command("docker", "logs", containerName)
	logs, _ := logsCmd.CombinedOutput()
	if len(logs) > 0 {
		t.Logf("Initial container logs:\n%s", string(logs))
		// Check if there are certificate errors
		if strings.Contains(string(logs), "No such file") || strings.Contains(string(logs), "Failed opening P12") {
			t.Logf("Certificate file error detected. Verifying certificate files exist...")
			// Verify files exist in the mounted directory
			listCmd := exec.Command("docker", "exec", containerName, "ls", "-la", "/certs")
			listOutput, _ := listCmd.CombinedOutput()
			t.Logf("Files in /certs:\n%s", string(listOutput))
		}
	}

	// Wait for container to be in running state
	t.Log("Waiting for container to be running...")
	maxWait := 15 * time.Second
	deadline := time.Now().Add(maxWait)
	containerRunning := false
	checkCount := 0
	for time.Now().Before(deadline) {
		checkCount++
		checkCmd := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", containerName)
		output, err := checkCmd.CombinedOutput()
		if err == nil {
			status := strings.TrimSpace(string(output))
			if status == "true" {
				containerRunning = true
				t.Logf("Container is running (checked %d times)", checkCount)
				break
			}
			if checkCount%5 == 0 {
				t.Logf("Container not running yet (status: %s, check %d)", status, checkCount)
				// Get logs periodically
				logsCmd := exec.Command("docker", "logs", "--tail", "20", containerName)
				logs, _ := logsCmd.CombinedOutput()
				if len(logs) > 0 {
					t.Logf("Recent logs:\n%s", string(logs))
				}
			}
		} else {
			// Container might not exist yet or was removed
			if checkCount%5 == 0 {
				t.Logf("Container check failed (attempt %d): %v", checkCount, err)
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !containerRunning {
		// Get final container logs and status
		t.Log("Container did not start successfully. Final diagnostics:")
		logsCmd := exec.Command("docker", "logs", containerName)
		logs, _ := logsCmd.CombinedOutput()
		t.Logf("Final container logs:\n%s", string(logs))

		statusCmd := exec.Command("docker", "inspect", "-f", "{{.State.Status}} {{.State.Error}}", containerName)
		status, _ := statusCmd.CombinedOutput()
		t.Logf("Final container status: %s", string(status))

		t.Fatal("Container did not start within timeout")
	}

	cleanup = func() {
		exec.Command("docker", "stop", containerName).Run()
		exec.Command("docker", "rm", "-f", containerName).Run()
	}

	// KMIP endpoint exposed via JSON over HTTP(S)
	endpoint = "http://localhost:9998"

	return containerID, endpoint, tlsCfg, cleanup, containerName, caCertPath
}

// waitForKMSReady waits for Cosmian KMS to be ready to accept connections.
func waitForKMSReady(t *testing.T, endpoint string, containerName string) {
	t.Helper()

	maxWait := 60 * time.Second
	checkInterval := 1 * time.Second
	deadline := time.Now().Add(maxWait)

	host, port := resolveHostPort(endpoint)
	t.Logf("Waiting for KMIP endpoint %s:%s to be ready...", host, port)
	attempts := 0
	for time.Now().Before(deadline) {
		attempts++
		// Try to connect to KMIP port (TLS) - this is the actual service we need
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
		if err == nil {
			conn.Close()
			t.Logf("KMIP port is accessible after %d attempts", attempts)
			// KMIP port is accessible, give it a moment to fully initialize
			time.Sleep(3 * time.Second)
			return
		}
		if attempts%10 == 0 {
			t.Logf("Still waiting for KMIP endpoint (attempt %d)...", attempts)
		}
		time.Sleep(checkInterval)
	}

	// Get container logs for debugging
	t.Logf("Cosmian KMS readiness check failed. Endpoint: %s", endpoint)
	if containerName != "" {
		t.Logf("Retrieving logs for container: %s", containerName)
		logsCmd := exec.Command("docker", "logs", containerName)
		logs, err := logsCmd.CombinedOutput()
		if err == nil {
			t.Logf("Container logs:\n%s", string(logs))
		} else {
			t.Logf("Failed to get container logs: %v", err)
		}

		// Check container status
		statusCmd := exec.Command("docker", "inspect", "-f", "{{.State.Status}} {{.State.Error}}", containerName)
		status, _ := statusCmd.CombinedOutput()
		t.Logf("Container status: %s", string(status))
	}
	t.Fatal("Cosmian KMS did not become ready within timeout - check Docker logs for container issues")
}

func resolveHostPort(endpoint string) (string, string) {
	if endpoint == "" {
		return "localhost", "9998"
	}
	if strings.Contains(endpoint, "://") {
		if u, err := url.Parse(endpoint); err == nil {
			host := u.Hostname()
			if host == "" {
				host = "localhost"
			}
			port := u.Port()
			if port == "" {
				if strings.EqualFold(u.Scheme, "https") {
					port = "443"
				} else {
					port = "80"
				}
			}
			return host, port
		}
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "localhost", endpoint
	}
	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = "9998"
	}
	return host, port
}

// createWrappingKey creates a wrapping key in Cosmian KMS using the Cosmian CLI.
// According to Cosmian documentation, keys created via CLI are usable for Encrypt operations.
// Returns the key ID for use in KMIP operations.
func createWrappingKey(t *testing.T, kmsEndpoint string) string {
	t.Helper()

	// Check if cosmian CLI is available
	cosmianPath, err := exec.LookPath("cosmian")
	if err != nil {
		t.Fatalf("Cosmian CLI not available in PATH: %v. Please install it from https://docs.cosmian.com/cosmian_cli/", err)
	}

	// Generate a unique tag for this test key
	tag := fmt.Sprintf("test-wrap-key-%d", time.Now().UnixNano())

	t.Logf("Creating wrapping key via Cosmian CLI with tag: %s", tag)

	// Use CLI to create key - simple command matching the user's working example
	// Format: cosmian kms sym keys create --number-of-bits 256 --algorithm aes --tag <tag>
	// The CLI will use default KMS URL from configuration or environment
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	args := []string{
		"kms", "sym", "keys", "create",
		"--number-of-bits", "256",
		"--algorithm", "aes",
		"--tag", tag,
	}
	if kmsEndpoint != "" {
		args = append([]string{"--kms-url", kmsEndpoint, "--accept-invalid-certs"}, args...)
	}

	cmd := exec.CommandContext(ctx, cosmianPath, args...)
	cmd.Env = os.Environ()

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Cosmian CLI failed to create key: %v\nOutput: %s", err, string(output))
	}

	// Parse output to extract unique identifier
	// Example output:
	// "The symmetric key was successfully generated.\n\t Unique identifier: 3ff383aa-8144-4e56-a6cd-9e71d5a791be"
	outputStr := string(output)
	t.Logf("Cosmian CLI output: %s", outputStr)

	// Look for "Unique identifier:" followed by UUID
	keyID := ""
	lines := strings.Split(outputStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Unique identifier:") {
			// Extract UUID from line like "	 Unique identifier: 3ff383aa-8144-4e56-a6cd-9e71d5a791be"
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "identifier:" && i+1 < len(parts) {
					keyID = parts[i+1]
					break
				}
			}
			break
		}
	}

	// Fallback: try to find UUID pattern anywhere in output
	if keyID == "" {
		// UUID pattern: 8-4-4-4-12 hex digits
		uuidPattern := `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`
		re := regexp.MustCompile(uuidPattern)
		matches := re.FindStringSubmatch(outputStr)
		if len(matches) > 0 {
			keyID = matches[0]
		}
	}

	require.NotEmpty(t, keyID, "Failed to extract key ID from CLI output: %s", outputStr)
	t.Logf("Created wrapping key via Cosmian CLI with ID: %s (tag: %s)", keyID, tag)

	// Give the key a moment to be fully registered
	time.Sleep(500 * time.Millisecond)

	return keyID
}

// TestCosmianKMSGatewayIntegration tests the full gateway with Cosmian KMS.
func TestCosmianKMSGatewayIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker not available, skipping integration test")
	}

	// Start Cosmian KMS with KMIP enabled
	_, kmsEndpoint, tlsCfg, kmsCleanup, containerName, _ := startCosmianKMS(t)
	defer kmsCleanup()

	waitForKMSReady(t, kmsEndpoint, containerName)

	// Start MinIO backend
	minioCleanup, minioEndpoint := startMinIO(t)
	defer minioCleanup()

	// Create wrapping key
	keyID := createWrappingKey(t, kmsEndpoint)

	manager, err := crypto.NewCosmianKMIPManager(crypto.CosmianKMIPOptions{
		Endpoint: kmsEndpoint,
		Keys: []crypto.KMIPKeyReference{
			{ID: keyID, Version: 1},
		},
		TLSConfig:      tlsCfg,
		Timeout:        10 * time.Second,
		Provider:       "cosmian",
		DualReadWindow: 1,
	})
	require.NoError(t, err)
	defer func() {
		_ = manager.Close(context.Background())
	}()

	// Create gateway config with KMS
	cfg := &config.Config{
		ListenAddr: ":0",
		LogLevel:   "error",
		Backend: config.BackendConfig{
			Endpoint:  minioEndpoint,
			AccessKey: "minioadmin",
			SecretKey: "minioadmin",
			Provider:  "minio",
			UseSSL:    false,
		},
		Encryption: config.EncryptionConfig{
			Password:           "fallback-password-123456",
			PreferredAlgorithm: "AES256-GCM",
			KeyManager: config.KeyManagerConfig{
				Enabled:        true,
				Provider:       "cosmian",
				DualReadWindow: 1,
				Cosmian: config.CosmianConfig{
					Endpoint:           kmsEndpoint,
					Timeout:            10 * time.Second,
					InsecureSkipVerify: true,
					Keys: []config.CosmianKeyReference{
						{ID: keyID, Version: 1},
					},
				},
			},
		},
	}

	// Start gateway with KMS
	gateway := StartGatewayWithKMS(t, cfg, manager)
	defer gateway.Close()

	// Test PUT with encryption
	bucket := "test-bucket"
	key := "test-object"
	content := []byte("Hello from gateway with Cosmian KMS!")

	// Create bucket directly in MinIO using AWS CLI
	createBucketInMinIOForGateway(t, minioEndpoint, bucket)

	// Give MinIO a moment to fully register the bucket
	time.Sleep(1 * time.Second)

	// Upload object
	putURL := fmt.Sprintf("%s/%s/%s", gateway.URL, bucket, key)
	req, err := http.NewRequest("PUT", putURL, bytes.NewReader(content))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Download and verify
	getURL := fmt.Sprintf("%s/%s/%s", gateway.URL, bucket, key)
	resp, err = http.Get(getURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	downloaded, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, content, downloaded)
}

// StartGatewayWithKMS starts a gateway server with KMS manager configured.
func StartGatewayWithKMS(t *testing.T, cfg *config.Config, manager crypto.KeyManager) *TestGateway {
	t.Helper()

	// Find available port
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	require.NoError(t, err)

	addr := listener.Addr().String()
	url := "http://" + addr

	// Initialize logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Initialize metrics
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)

	// Initialize S3 client
	var s3Client s3.Client
	if !cfg.Backend.UseClientCredentials {
		s3Client, err = s3.NewClient(&cfg.Backend)
		require.NoError(t, err)
	}

	// Initialize encryption engine
	encryptionPassword := cfg.Encryption.Password
	if encryptionPassword == "" {
		encryptionPassword = "test-password-123456"
	}

	var compressionEngine crypto.CompressionEngine
	if cfg.Compression.Enabled {
		compressionEngine = crypto.NewCompressionEngine(
			cfg.Compression.Enabled,
			cfg.Compression.MinSize,
			cfg.Compression.ContentTypes,
			cfg.Compression.Algorithm,
			cfg.Compression.Level,
		)
	}

	encryptionEngine, err := crypto.NewEngineWithCompression(encryptionPassword, compressionEngine)
	require.NoError(t, err)

	// Wire KMS manager into engine
	crypto.SetKeyManager(encryptionEngine, manager)

	// Initialize API handler
	handler := api.NewHandlerWithFeatures(s3Client, encryptionEngine, logger, m, nil, nil, nil, cfg, nil)

	// Setup router
	router := mux.NewRouter()
	router.Handle("/metrics", m.Handler()).Methods("GET")
	handler.RegisterRoutes(router)

	// Apply middleware
	httpHandler := middleware.RecoveryMiddleware(logger)(router)
	httpHandler = middleware.LoggingMiddleware(logger, &cfg.Logging)(httpHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:              addr,
		Handler:           httpHandler,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}

	// Start server
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()

	// Wait for server to be ready
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			listener.Close()
			t.Fatal("Timeout waiting for gateway to start")
		default:
			resp, err := http.Get(url + "/health")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					goto ready
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

ready:
	client := &http.Client{Timeout: 30 * time.Second}

	return &TestGateway{
		Addr:     addr,
		URL:      url,
		server:   server,
		client:   client,
		listener: listener,
	}
}

// startMinIO starts a MinIO container for testing.
// Uses dynamic port allocation to avoid conflicts.
func startMinIO(t *testing.T) (cleanup func(), endpoint string) {
	t.Helper()

	containerName := fmt.Sprintf("minio-test-%d", time.Now().UnixNano())

	// Clean up any existing containers with the same name pattern
	exec.Command("docker", "stop", containerName).Run()
	exec.Command("docker", "rm", "-f", containerName).Run()

	// Use dynamic port allocation (Docker will assign available ports)
	// Format: -p container_port (Docker assigns random host port)
	cmd := exec.Command("docker", "run", "-d",
		"--name", containerName,
		"-p", "9000/tcp", // Let Docker assign available host port
		"-p", "9001/tcp", // Let Docker assign available host port
		"-e", "MINIO_ROOT_USER=minioadmin",
		"-e", "MINIO_ROOT_PASSWORD=minioadmin",
		"--rm",
		"minio/minio:latest",
		"server", "/data", "--console-address", ":9001")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to start MinIO: %s", string(output))

	// Wait for container to start
	time.Sleep(2 * time.Second)

	// Get the actual port mapping
	inspectCmd := exec.Command("docker", "port", containerName, "9000/tcp")
	portOutput, err := inspectCmd.CombinedOutput()
	require.NoError(t, err, "Failed to get MinIO port mapping: %s", string(portOutput))

	// Parse port from output (format: "0.0.0.0:49153\n[::]:49153" - multiple lines for IPv4 and IPv6)
	portMapping := strings.TrimSpace(string(portOutput))
	lines := strings.Split(portMapping, "\n")
	// Use the first line (IPv4)
	if len(lines) > 0 {
		portMapping = lines[0]
	}
	// Extract port from "0.0.0.0:49153" or "[::]:49153"
	lastColon := strings.LastIndex(portMapping, ":")
	require.Greater(t, lastColon, 0, "Unexpected port mapping format: %s", portMapping)
	port := portMapping[lastColon+1:]
	endpoint = fmt.Sprintf("http://localhost:%s", port)

	// Wait for MinIO to be ready
	time.Sleep(2 * time.Second)

	return func() {
		exec.Command("docker", "stop", containerName).Run()
		exec.Command("docker", "rm", "-f", containerName).Run()
	}, endpoint
}

// createBucketInMinIOForGateway creates a bucket directly in MinIO using AWS CLI.
// This is needed because the gateway may not support bucket creation operations.
func createBucketInMinIOForGateway(t *testing.T, minioEndpoint, bucket string) {
	t.Helper()

	// Set AWS CLI configuration for MinIO
	cmd := exec.Command("aws", "configure", "set", "aws_access_key_id", "minioadmin")
	if err := cmd.Run(); err != nil {
		t.Logf("Warning: Failed to configure AWS CLI access key: %v", err)
	}

	cmd = exec.Command("aws", "configure", "set", "aws_secret_access_key", "minioadmin")
	if err := cmd.Run(); err != nil {
		t.Logf("Warning: Failed to configure AWS CLI secret key: %v", err)
	}

	cmd = exec.Command("aws", "configure", "set", "region", "us-east-1")
	if err := cmd.Run(); err != nil {
		t.Logf("Warning: Failed to configure AWS CLI region: %v", err)
	}

	// Try to create bucket using AWS CLI
	for attempts := 0; attempts < 5; attempts++ {
		cmd := exec.Command("aws", "s3", "mb", fmt.Sprintf("s3://%s", bucket),
			"--endpoint-url", minioEndpoint,
			"--no-verify-ssl")
		output, err := cmd.CombinedOutput()
		if err == nil {
			return
		}
		// Check if bucket already exists (which is OK)
		outputStr := string(output)
		if strings.Contains(outputStr, "BucketAlreadyOwnedByYou") || strings.Contains(outputStr, "BucketAlreadyExists") {
			return
		}
		if attempts < 4 {
			time.Sleep(time.Duration(attempts+1) * 500 * time.Millisecond)
		}
	}
	t.Logf("Warning: Could not create bucket %s with AWS CLI, proceeding anyway", bucket)
}
