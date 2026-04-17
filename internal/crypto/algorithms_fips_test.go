//go:build fips

package crypto

import (
	"crypto/fips140"
	"errors"
	"testing"
)

// TestChaCha20Rejected verifies that ChaCha20-Poly1305 cannot be used in FIPS mode.
func TestChaCha20Rejected(t *testing.T) {
	key := make([]byte, chacha20KeySize)
	for i := range key {
		key[i] = 0x01
	}

	cipher, err := createAEADCipher(AlgorithmChaCha20Poly1305, key)
	if err == nil {
		t.Fatal("expected ChaCha20-Poly1305 to be rejected in FIPS mode, but it succeeded")
	}
	if cipher != nil {
		t.Errorf("expected nil cipher on error, got %v", cipher)
	}

	// Verify the error is ErrAlgorithmNotApproved
	if !errors.Is(err, ErrAlgorithmNotApproved) {
		t.Errorf("expected ErrAlgorithmNotApproved, got %v", err)
	}
}

// TestAESGCMApproved verifies that AES-256-GCM works in FIPS mode.
func TestAESGCMApproved(t *testing.T) {
	key := make([]byte, aesKeySize)
	for i := range key {
		key[i] = 0x02
	}

	cipher, err := createAEADCipher(AlgorithmAES256GCM, key)
	if err != nil {
		t.Fatalf("AES-256-GCM should be approved in FIPS mode: %v", err)
	}
	if cipher == nil {
		t.Fatal("expected non-nil cipher for AES-256-GCM")
	}
	if cipher.Algorithm() != AlgorithmAES256GCM {
		t.Errorf("expected algorithm %s, got %s", AlgorithmAES256GCM, cipher.Algorithm())
	}

	// Test a round-trip encrypt/decrypt
	nonce := make([]byte, nonceSize)
	for i := range nonce {
		nonce[i] = 0x03
	}

	plaintext := []byte("Hello, FIPS world!")
	aad := []byte("additional authenticated data")

	ciphertext := cipher.Seal(nil, nonce, plaintext, aad)
	if len(ciphertext) == 0 {
		t.Fatal("encryption failed")
	}

	decrypted, err := cipher.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("round-trip mismatch: expected %q, got %q", plaintext, decrypted)
	}
}

// TestFIPSRuntimeEnabled verifies that the FIPS runtime module is active.
func TestFIPSRuntimeEnabled(t *testing.T) {
	if !fips140.Enabled() {
		t.Fatal("FIPS 140-3 module is not enabled at runtime; " +
			"ensure GOFIPS140=v1.0.0 is set in the test environment")
	}

	if !FIPSEnabled() {
		t.Fatal("FIPSEnabled() returned false, but crypto/fips140.Enabled() is true")
	}
}

// TestAssertFIPSSucceeds verifies that AssertFIPS succeeds in a FIPS build.
func TestAssertFIPSSucceeds(t *testing.T) {
	err := AssertFIPS()
	if err != nil {
		t.Fatalf("AssertFIPS() failed in FIPS mode: %v", err)
	}
}

// TestDefaultAlgorithmConfigFIPS verifies that the default config excludes ChaCha20 in FIPS mode.
func TestDefaultAlgorithmConfigFIPS(t *testing.T) {
	cfg := DefaultAlgorithmConfig()

	if cfg.PreferredAlgorithm != AlgorithmAES256GCM {
		t.Errorf("expected preferred algorithm %s, got %s", AlgorithmAES256GCM, cfg.PreferredAlgorithm)
	}

	if len(cfg.SupportedAlgorithms) != 1 {
		t.Errorf("expected 1 supported algorithm in FIPS mode, got %d", len(cfg.SupportedAlgorithms))
	}

	for _, alg := range cfg.SupportedAlgorithms {
		if alg == AlgorithmChaCha20Poly1305 {
			t.Fatal("ChaCha20-Poly1305 should not be in supported algorithms in FIPS mode")
		}
	}
}
