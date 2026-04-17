//go:build !fips

package crypto

import (
	"crypto/rand"
	"testing"
)

// TestCreateAEADCipher_ChaCha20Poly1305 verifies ChaCha20-Poly1305 cipher
// construction in non-FIPS builds. The FIPS build intentionally rejects this
// algorithm (see algorithms_fips_test.go:TestChaCha20Rejected).
func TestCreateAEADCipher_ChaCha20Poly1305(t *testing.T) {
	key := make([]byte, chacha20KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cipher, err := createAEADCipher(AlgorithmChaCha20Poly1305, key)
	if err != nil {
		t.Fatalf("failed to create ChaCha20-Poly1305 cipher: %v", err)
	}

	if cipher.Algorithm() != AlgorithmChaCha20Poly1305 {
		t.Fatalf("expected algorithm %s, got %s", AlgorithmChaCha20Poly1305, cipher.Algorithm())
	}
}
