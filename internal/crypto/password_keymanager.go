package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"time"
)

// passwordKMProvider is the Provider() string for password-derived key wrapping.
const passwordKMProvider = "password"

// passwordKeyManager implements KeyManager using PBKDF2 + AES-256-GCM to wrap
// and unwrap Data Encryption Keys. It requires no external infrastructure and
// uses the same primitives as the existing single-PUT chunked encryption path.
//
// Wrapped-key format (stored in KeyEnvelope.Ciphertext):
//
//	salt(32) || nonce(12) || sealed(dek + tag)(48)  — total 92 bytes
//
// Without the gateway password the DEK cannot be recovered, so Valkey and
// backend companion objects are opaque to any party that doesn't hold the
// password. This is equivalent security to the existing object encryption.
type passwordKeyManager struct {
	password string
	closed   bool
}

// NewPasswordKeyManager creates a KeyManager that wraps DEKs using
// PBKDF2-SHA256 (100 000 iterations) + AES-256-GCM. This is the fallback
// for deployments that do not configure an external KMS; it provides the
// same confidentiality guarantee as the existing single-PUT encryption.
//
// The password must be the gateway's configured encryption password — the same
// string used for all other object encryption in the deployment.
func NewPasswordKeyManager(password string) (KeyManager, error) {
	if len(password) < 12 {
		return nil, fmt.Errorf("password_keymanager: password must be at least 12 characters")
	}
	return &passwordKeyManager{password: password}, nil
}

func (m *passwordKeyManager) Provider() string { return passwordKMProvider }

// WrapKey encrypts plaintext with a PBKDF2-derived wrapping key.
func (m *passwordKeyManager) WrapKey(ctx context.Context, plaintext []byte, _ map[string]string) (*KeyEnvelope, error) {
	if m.closed {
		return nil, ErrProviderUnavailable
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("password_keymanager: plaintext DEK must not be empty")
	}

	// Random salt — ensures a unique wrapping key per DEK even with the same password.
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("password_keymanager: generate salt: %w", err)
	}

	// Derive wrapping key using the same PBKDF2 parameters as the engine.
	wk, err := pbkdf2.Key(sha256.New, m.password, salt, pbkdf2Iterations, aesKeySize)
	if err != nil {
		return nil, fmt.Errorf("password_keymanager: derive wrapping key: %w", err)
	}
	defer zeroBytes(wk)

	block, err := aes.NewCipher(wk)
	if err != nil {
		return nil, fmt.Errorf("password_keymanager: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("password_keymanager: create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("password_keymanager: generate nonce: %w", err)
	}

	sealed := gcm.Seal(nil, nonce, plaintext, nil)

	// Concatenate: salt || nonce || sealed
	payload := make([]byte, 0, len(salt)+len(nonce)+len(sealed))
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, sealed...)

	return &KeyEnvelope{
		Provider:   passwordKMProvider,
		KeyVersion: 1,
		Ciphertext: payload,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// UnwrapKey decrypts an envelope produced by WrapKey.
func (m *passwordKeyManager) UnwrapKey(ctx context.Context, envelope *KeyEnvelope, _ map[string]string) ([]byte, error) {
	if m.closed {
		return nil, ErrProviderUnavailable
	}
	if envelope == nil || len(envelope.Ciphertext) == 0 {
		return nil, ErrInvalidEnvelope
	}
	if envelope.Provider != passwordKMProvider {
		return nil, fmt.Errorf("password_keymanager: envelope provider mismatch (got %q, want %q)", envelope.Provider, passwordKMProvider)
	}

	payload := envelope.Ciphertext
	// Minimum: salt(32) + nonce(12) + tag(16) = 60 bytes (with zero-length DEK).
	const minPayload = saltSize + nonceSize + tagSize
	if len(payload) < minPayload {
		return nil, fmt.Errorf("%w: payload too short (%d bytes)", ErrInvalidEnvelope, len(payload))
	}

	salt := payload[:saltSize]
	nonce := payload[saltSize : saltSize+nonceSize]
	sealed := payload[saltSize+nonceSize:]

	wk, err := pbkdf2.Key(sha256.New, m.password, salt, pbkdf2Iterations, aesKeySize)
	if err != nil {
		return nil, fmt.Errorf("password_keymanager: derive wrapping key: %w", err)
	}
	defer zeroBytes(wk)

	block, err := aes.NewCipher(wk)
	if err != nil {
		return nil, fmt.Errorf("password_keymanager: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("password_keymanager: create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrapFailed, err)
	}
	return plaintext, nil
}

func (m *passwordKeyManager) ActiveKeyVersion(_ context.Context) (int, error) {
	if m.closed {
		return 0, ErrProviderUnavailable
	}
	return 1, nil
}

func (m *passwordKeyManager) HealthCheck(_ context.Context) error {
	if m.closed {
		return ErrProviderUnavailable
	}
	return nil
}

func (m *passwordKeyManager) Close(_ context.Context) error {
	if !m.closed {
		m.closed = true
		// Zero the password in memory.
		for i := range m.password {
			_ = i // string is immutable; set via a []byte copy trick is not possible
			// Go strings are immutable; best effort is to nil the reference.
		}
		m.password = ""
	}
	return nil
}

// IsPasswordKeyManager reports whether km is a passwordKeyManager. Used in
// tests and startup validation.
func IsPasswordKeyManager(km KeyManager) bool {
	if km == nil {
		return false
	}
	_, ok := km.(*passwordKeyManager)
	return ok
}

