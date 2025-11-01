package crypto

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"io"
)

// decryptReader implements streaming decryption using AES-GCM.
// Since GCM requires authentication of the entire message, we read
// the full ciphertext, decrypt it, then stream the decrypted result.
type decryptReader struct {
	buffer *bytes.Buffer
}

// newDecryptReader creates a new decryptReader for streaming decryption.
func newDecryptReader(source io.Reader, gcm cipher.AEAD, iv []byte) (*decryptReader, error) {
	// Read all encrypted data from source
	ciphertext, err := io.ReadAll(source)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}

	// Check minimum size (should have at least some ciphertext)
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("empty ciphertext")
	}

	// Decrypt the data using GCM
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return &decryptReader{
		buffer: bytes.NewBuffer(plaintext),
	}, nil
}

// Read reads decrypted data from the buffer.
func (r *decryptReader) Read(p []byte) (int, error) {
	return r.buffer.Read(p)
}
