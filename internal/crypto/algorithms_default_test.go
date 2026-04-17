//go:build !fips

package crypto

import (
	"testing"
)

// TestChaCha20Registered verifies that ChaCha20-Poly1305 is registered in default (non-FIPS) builds.
func TestChaCha20Registered(t *testing.T) {
	key := make([]byte, chacha20KeySize)
	for i := range key {
		key[i] = 0x01
	}

	cipher, err := createAEADCipher(AlgorithmChaCha20Poly1305, key)
	if err != nil {
		t.Fatalf("ChaCha20-Poly1305 should be available in default builds: %v", err)
	}
	if cipher == nil {
		t.Fatal("expected non-nil cipher for ChaCha20-Poly1305")
	}
	if cipher.Algorithm() != AlgorithmChaCha20Poly1305 {
		t.Errorf("expected algorithm %s, got %s", AlgorithmChaCha20Poly1305, cipher.Algorithm())
	}
}

// TestBothAlgorithmsAvailable verifies that both AES-GCM and ChaCha20 are available in default builds.
func TestBothAlgorithmsAvailable(t *testing.T) {
	testCases := []struct {
		alg     string
		keySize int
	}{
		{AlgorithmAES256GCM, aesKeySize},
		{AlgorithmChaCha20Poly1305, chacha20KeySize},
	}

	for _, tc := range testCases {
		t.Run(tc.alg, func(t *testing.T) {
			key := make([]byte, tc.keySize)
			for i := range key {
				key[i] = 0x42
			}

			cipher, err := createAEADCipher(tc.alg, key)
			if err != nil {
				t.Fatalf("algorithm %s should be available: %v", tc.alg, err)
			}
			if cipher == nil {
				t.Fatalf("expected non-nil cipher for %s", tc.alg)
			}
			if cipher.Algorithm() != tc.alg {
				t.Errorf("expected algorithm %s, got %s", tc.alg, cipher.Algorithm())
			}
		})
	}
}

// TestFIPSDisabled verifies that FIPSEnabled() returns false in non-FIPS builds.
func TestFIPSDisabled(t *testing.T) {
	if FIPSEnabled() {
		t.Fatal("FIPSEnabled() returned true in a non-FIPS build")
	}
}

// TestAssertFIPSSucceedsInDefault verifies that AssertFIPS is a no-op in non-FIPS builds.
func TestAssertFIPSSucceedsInDefault(t *testing.T) {
	err := AssertFIPS()
	if err != nil {
		t.Fatalf("AssertFIPS() should be a no-op in non-FIPS builds, got error: %v", err)
	}
}

// TestDefaultAlgorithmConfigDefault verifies that both algorithms are in the default config.
func TestDefaultAlgorithmConfigDefault(t *testing.T) {
	cfg := DefaultAlgorithmConfig()

	if cfg.PreferredAlgorithm != AlgorithmAES256GCM {
		t.Errorf("expected preferred algorithm %s, got %s", AlgorithmAES256GCM, cfg.PreferredAlgorithm)
	}

	if len(cfg.SupportedAlgorithms) != 2 {
		t.Errorf("expected 2 supported algorithms in default build, got %d", len(cfg.SupportedAlgorithms))
	}

	hasAES := false
	hasChaCha := false
	for _, alg := range cfg.SupportedAlgorithms {
		if alg == AlgorithmAES256GCM {
			hasAES = true
		}
		if alg == AlgorithmChaCha20Poly1305 {
			hasChaCha = true
		}
	}

	if !hasAES {
		t.Fatal("AES-256-GCM should be in supported algorithms")
	}
	if !hasChaCha {
		t.Fatal("ChaCha20-Poly1305 should be in supported algorithms in default build")
	}
}
