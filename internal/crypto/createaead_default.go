//go:build !fips

package crypto

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// createAEADCipher creates an AEAD cipher for the given algorithm and key.
// In non-FIPS builds, both AES-256-GCM and ChaCha20-Poly1305 are available.
func createAEADCipher(algorithm string, key []byte) (AEADCipher, error) {
	switch algorithm {
	case AlgorithmAES256GCM:
		return createAESGCMCipher(key)
	case AlgorithmChaCha20Poly1305:
		return createChaCha20Poly1305Cipher(key)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// createChaCha20Poly1305Cipher creates a ChaCha20-Poly1305 cipher.
func createChaCha20Poly1305Cipher(key []byte) (AEADCipher, error) {
	if len(key) != chacha20KeySize {
		return nil, fmt.Errorf("invalid key size for ChaCha20: expected %d bytes, got %d", chacha20KeySize, len(key))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	return &chacha20Poly1305Cipher{AEAD: aead}, nil
}
