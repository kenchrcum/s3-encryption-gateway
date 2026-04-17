//go:build fips

package crypto

import (
	"fmt"
)

// createAEADCipher creates an AEAD cipher for the given algorithm and key.
// In FIPS mode, only AES-256-GCM is available. ChaCha20-Poly1305 is rejected
// as it is not on the FIPS 140-3 approved list.
func createAEADCipher(algorithm string, key []byte) (AEADCipher, error) {
	switch algorithm {
	case AlgorithmAES256GCM:
		return createAESGCMCipher(key)
	case AlgorithmChaCha20Poly1305:
		return nil, ErrAlgorithmNotApproved
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// createChaCha20Poly1305Cipher is not available in FIPS mode.
func createChaCha20Poly1305Cipher(key []byte) (AEADCipher, error) {
	return nil, ErrAlgorithmNotApproved
}
