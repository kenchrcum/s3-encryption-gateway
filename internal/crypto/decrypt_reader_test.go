package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"
)

// makeTestAEAD creates a fresh AES-256-GCM AEAD for testing.
func makeTestAEAD(t *testing.T) (cipher.AEAD, []byte) {
	t.Helper()
	key := make([]byte, 32) // AES-256
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	return gcm, key
}

// encryptForTest encrypts plaintext with the given AEAD and nonce.
// Returns the raw ciphertext (nonce NOT prepended — decryptReader reads nonce separately).
func encryptForTest(t *testing.T, gcm cipher.AEAD, nonce, plaintext []byte) []byte {
	t.Helper()
	return gcm.Seal(nil, nonce, plaintext, nil)
}

// TestDecryptReader_RoundTrip verifies that data encrypted with AES-GCM
// and then decrypted by newDecryptReader is byte-identical to the original.
func TestDecryptReader_RoundTrip(t *testing.T) {
	sizes := []int{0, 1, 15, 16, 64, 1024, 65536}

	for _, size := range sizes {
		t.Run("", func(t *testing.T) {
			gcm, _ := makeTestAEAD(t)
			nonce := make([]byte, gcm.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				t.Fatalf("rand.Read nonce: %v", err)
			}

			// Handle the special case: size=0 would produce empty plaintext.
			// GCM of empty plaintext is still valid (just the authentication tag).
			var plaintext []byte
			if size > 0 {
				plaintext = make([]byte, size)
				if _, err := rand.Read(plaintext); err != nil {
					t.Fatalf("rand.Read plaintext: %v", err)
				}
			}

			// Only test sizes > 0 (empty ciphertext is rejected by newDecryptReader)
			if size == 0 {
				// Empty ciphertext → error from newDecryptReader
				dr, err := newDecryptReader(bytes.NewReader([]byte{}), gcm, nonce)
				if err == nil {
					t.Error("newDecryptReader() with empty ciphertext: expected error, got nil")
				}
				if dr != nil {
					t.Error("newDecryptReader() with empty ciphertext: expected nil reader")
				}
				return
			}

			ciphertext := encryptForTest(t, gcm, nonce, plaintext)

			dr, err := newDecryptReader(bytes.NewReader(ciphertext), gcm, nonce)
			if err != nil {
				t.Fatalf("newDecryptReader() error: %v (size=%d)", err, size)
			}
			if dr == nil {
				t.Fatal("newDecryptReader() returned nil reader")
			}

			decrypted, err := io.ReadAll(dr)
			if err != nil {
				t.Fatalf("ReadAll() error: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("decrypted data does not match original (size=%d)", size)
			}
		})
	}
}

// TestDecryptReader_RoundTrip_64KiB exercises the plan's specifically-listed
// test case: a 64 KiB payload.
func TestDecryptReader_RoundTrip_64KiB(t *testing.T) {
	gcm, _ := makeTestAEAD(t)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read nonce: %v", err)
	}

	plaintext := make([]byte, 64*1024)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("rand.Read plaintext: %v", err)
	}

	ciphertext := encryptForTest(t, gcm, nonce, plaintext)

	dr, err := newDecryptReader(bytes.NewReader(ciphertext), gcm, nonce)
	if err != nil {
		t.Fatalf("newDecryptReader(64KiB) error: %v", err)
	}

	decrypted, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("ReadAll(64KiB) error: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("64KiB round-trip: decrypted data does not match original")
	}
}

// TestDecryptReader_TamperedCiphertext verifies that newDecryptReader returns
// an error when the ciphertext has been tampered with (GCM authentication fails).
func TestDecryptReader_TamperedCiphertext(t *testing.T) {
	gcm, _ := makeTestAEAD(t)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read nonce: %v", err)
	}

	plaintext := []byte("sensitive data")
	ciphertext := encryptForTest(t, gcm, nonce, plaintext)

	// Tamper with the ciphertext (flip a bit in the middle)
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	if len(tampered) > 0 {
		tampered[len(tampered)/2] ^= 0xFF
	}

	_, err := newDecryptReader(bytes.NewReader(tampered), gcm, nonce)
	if err == nil {
		t.Fatal("newDecryptReader() with tampered ciphertext: expected error, got nil")
	}
}

// TestDecryptReader_WrongNonce verifies that decryption with the wrong nonce
// fails (GCM authentication).
func TestDecryptReader_WrongNonce(t *testing.T) {
	gcm, _ := makeTestAEAD(t)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read nonce: %v", err)
	}

	plaintext := []byte("sensitive data")
	ciphertext := encryptForTest(t, gcm, nonce, plaintext)

	// Use a different (wrong) nonce for decryption
	wrongNonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(wrongNonce); err != nil {
		t.Fatalf("rand.Read wrongNonce: %v", err)
	}

	_, err := newDecryptReader(bytes.NewReader(ciphertext), gcm, wrongNonce)
	if err == nil {
		t.Fatal("newDecryptReader() with wrong nonce: expected error, got nil")
	}
}

// TestDecryptReader_Read_Multiple verifies that multiple Read() calls from the
// decryptReader produce all the plaintext bytes (buffer boundary testing).
func TestDecryptReader_Read_Multiple(t *testing.T) {
	gcm, _ := makeTestAEAD(t)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read nonce: %v", err)
	}

	plaintext := bytes.Repeat([]byte("ABCDEFGHIJKLMNOP"), 64) // 1024 bytes
	ciphertext := encryptForTest(t, gcm, nonce, plaintext)

	dr, err := newDecryptReader(bytes.NewReader(ciphertext), gcm, nonce)
	if err != nil {
		t.Fatalf("newDecryptReader() error: %v", err)
	}

	// Read in small 7-byte chunks to exercise buffer boundary handling
	var result bytes.Buffer
	buf := make([]byte, 7)
	for {
		n, err := dr.Read(buf)
		if n > 0 {
			result.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read() error: %v", err)
		}
	}

	if !bytes.Equal(result.Bytes(), plaintext) {
		t.Errorf("multi-read: decrypted data does not match original")
	}
}
