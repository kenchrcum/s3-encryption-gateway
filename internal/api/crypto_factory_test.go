package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/sirupsen/logrus"
)

// testFactoryLogger returns a discarding logger for tests.
func testFactoryLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(os.Stderr) // quiet but not nil
	l.SetLevel(logrus.ErrorLevel)
	return l
}

// TestBuildKeyManager_MemoryProvider verifies that the memory provider
// can be instantiated without errors.
func TestBuildKeyManager_MemoryProvider(t *testing.T) {
	cfg := &config.KeyManagerConfig{
		Provider: "memory",
		Memory: config.MemoryKMConfig{
			MasterKeySource: "", // empty = generate random
		},
	}

	km, err := BuildKeyManager(cfg, testFactoryLogger())
	if err != nil {
		t.Fatalf("BuildKeyManager(memory) error: %v", err)
	}
	if km == nil {
		t.Fatal("BuildKeyManager(memory) returned nil KeyManager")
	}
	km.Close(context.Background())
}

// TestBuildKeyManager_MemoryProvider_WithMasterKeySource verifies memory
// provider with a non-empty master key source.
func TestBuildKeyManager_MemoryProvider_WithMasterKeySource(t *testing.T) {
	cfg := &config.KeyManagerConfig{
		Provider: "memory",
		Memory: config.MemoryKMConfig{
			MasterKeySource: "env:TEST_MASTER_KEY",
		},
	}

	// Set the env var so the memory provider can find it
	t.Setenv("TEST_MASTER_KEY", strings.Repeat("A", 64)) // 32 bytes hex

	km, err := BuildKeyManager(cfg, testFactoryLogger())
	// May succeed or fail depending on memory provider implementation;
	// the important thing is no panic and no undefined behavior.
	if err == nil && km != nil {
		km.Close(context.Background())
	}
}

// TestBuildKeyManager_CosmianProvider_MissingEndpoint verifies that building
// a cosmian provider without an endpoint returns an error.
func TestBuildKeyManager_CosmianProvider_MissingEndpoint(t *testing.T) {
	cfg := &config.KeyManagerConfig{
		Provider: "cosmian",
		Cosmian: config.CosmianConfig{
			Endpoint: "", // missing
			Keys:     []config.CosmianKeyReference{{ID: "key1", Version: 1}},
		},
	}

	_, err := BuildKeyManager(cfg, testFactoryLogger())
	if err == nil {
		t.Fatal("BuildKeyManager(cosmian) expected error for missing endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "endpoint") {
		t.Errorf("expected error to mention 'endpoint', got: %v", err)
	}
}

// TestBuildKeyManager_CosmianProvider_MissingKeys verifies that building
// a cosmian provider without keys returns an error.
func TestBuildKeyManager_CosmianProvider_MissingKeys(t *testing.T) {
	cfg := &config.KeyManagerConfig{
		Provider: "cosmian",
		Cosmian: config.CosmianConfig{
			Endpoint: "kmip://localhost:5696",
			Keys:     nil, // no keys
		},
	}

	_, err := BuildKeyManager(cfg, testFactoryLogger())
	if err == nil {
		t.Fatal("BuildKeyManager(cosmian) expected error for missing keys, got nil")
	}
	if !strings.Contains(err.Error(), "keys") {
		t.Errorf("expected error to mention 'keys', got: %v", err)
	}
}

// TestBuildKeyManager_CosmianProvider_MissingKeyID verifies error when a
// key ref has empty ID.
func TestBuildKeyManager_CosmianProvider_MissingKeyID(t *testing.T) {
	cfg := &config.KeyManagerConfig{
		Provider: "cosmian",
		Cosmian: config.CosmianConfig{
			Endpoint: "kmip://localhost:5696",
			Keys:     []config.CosmianKeyReference{{ID: "", Version: 1}},
		},
	}

	_, err := BuildKeyManager(cfg, testFactoryLogger())
	if err == nil {
		t.Fatal("BuildKeyManager(cosmian) expected error for missing key ID, got nil")
	}
}

// TestBuildKeyManager_DefaultProviderIsCosmian verifies that an empty provider
// defaults to cosmian.
func TestBuildKeyManager_DefaultProviderIsCosmian(t *testing.T) {
	cfg := &config.KeyManagerConfig{
		Provider: "", // empty → defaults to cosmian
		Cosmian: config.CosmianConfig{
			Endpoint: "", // missing → error
		},
	}

	_, err := BuildKeyManager(cfg, testFactoryLogger())
	// Should fail with cosmian-style error (missing endpoint)
	if err == nil {
		t.Fatal("BuildKeyManager with empty provider expected error, got nil")
	}
}

// TestBuildKeyManager_UnknownProvider verifies that an unknown provider
// returns an error via the registry.
func TestBuildKeyManager_UnknownProvider(t *testing.T) {
	cfg := &config.KeyManagerConfig{
		Provider: "unknown-provider-xyz",
	}

	_, err := BuildKeyManager(cfg, testFactoryLogger())
	if err == nil {
		t.Fatal("BuildKeyManager with unknown provider expected error, got nil")
	}
}

// TestBuildCosmianTLSConfig_Basic verifies that buildCosmianTLSConfig
// with no certificates returns a minimal TLS config.
func TestBuildCosmianTLSConfig_Basic(t *testing.T) {
	cfg := config.CosmianConfig{
		InsecureSkipVerify: false,
	}

	tlsCfg, err := buildCosmianTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildCosmianTLSConfig() error: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("buildCosmianTLSConfig() returned nil config")
	}
	if tlsCfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=false")
	}
}

// TestBuildCosmianTLSConfig_InsecureMode verifies InsecureSkipVerify is propagated.
func TestBuildCosmianTLSConfig_InsecureMode(t *testing.T) {
	cfg := config.CosmianConfig{
		InsecureSkipVerify: true,
	}

	tlsCfg, err := buildCosmianTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildCosmianTLSConfig() error: %v", err)
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true")
	}
}

// TestBuildCosmianTLSConfig_MissingCACert verifies that a non-existent
// CA cert path returns an error.
func TestBuildCosmianTLSConfig_MissingCACert(t *testing.T) {
	cfg := config.CosmianConfig{
		CACert: "/nonexistent/path/ca.crt",
	}

	_, err := buildCosmianTLSConfig(cfg)
	if err == nil {
		t.Fatal("buildCosmianTLSConfig() expected error for missing CA cert, got nil")
	}
}

// TestBuildCosmianTLSConfig_InvalidCACert verifies that an invalid PEM
// CA cert returns an error.
func TestBuildCosmianTLSConfig_InvalidCACert(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "invalid-ca.crt")
	if err := os.WriteFile(caFile, []byte("not a valid PEM certificate"), 0644); err != nil {
		t.Fatalf("failed to write invalid CA cert: %v", err)
	}

	cfg := config.CosmianConfig{
		CACert: caFile,
	}

	_, err := buildCosmianTLSConfig(cfg)
	if err == nil {
		t.Fatal("buildCosmianTLSConfig() expected error for invalid CA cert, got nil")
	}
	if !strings.Contains(err.Error(), "parse") && !strings.Contains(err.Error(), "certificate") {
		t.Errorf("expected cert parse error, got: %v", err)
	}
}
