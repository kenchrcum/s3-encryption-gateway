package crypto

import (
	"context"
	"errors"
	"time"
)

// KeyManager abstracts an external Key Management System that wraps/unwraps
// per-object Data Encryption Keys (DEKs).
//
// Invariants (MUST hold for every implementation):
//  1. All methods are safe for concurrent use by multiple goroutines.
//  2. ctx is honoured: implementations MUST use ctx for any blocking I/O
//     and return ctx.Err() wrapped when cancellation occurs.
//  3. Plaintext DEKs returned by UnwrapKey MUST be owned by the caller; the
//     caller is responsible for zeroization. Implementations MUST NOT retain
//     a reference to the returned slice. Implementations SHOULD zeroize any
//     internal copies before returning.
//  4. WrapKey MUST NOT log or export plaintext input.
//  5. Close is idempotent; subsequent calls return nil. After Close, all
//     other methods MUST return ErrProviderUnavailable.
//  6. A nil KeyManager is never valid; callers must check.
type KeyManager interface {
	// Provider returns a short identifier (e.g. "cosmian-kmip") used for
	// diagnostics and metadata.
	Provider() string

	// WrapKey encrypts the provided plaintext DEK and returns an envelope
	// suitable for persisting alongside the encrypted object metadata.
	WrapKey(ctx context.Context, plaintext []byte, metadata map[string]string) (*KeyEnvelope, error)

	// UnwrapKey decrypts the ciphertext contained in the given envelope and
	// returns the plaintext DEK. The returned slice is owned by the caller,
	// who must zeroize it when done.
	UnwrapKey(ctx context.Context, envelope *KeyEnvelope, metadata map[string]string) ([]byte, error)

	// ActiveKeyVersion returns the version identifier of the primary wrapping key.
	ActiveKeyVersion(ctx context.Context) (int, error)

	// HealthCheck verifies that the KMS is accessible and operational.
	// Returns an error if the KMS is unavailable or unhealthy.
	// This should be a lightweight operation that does not perform actual
	// encryption/decryption.
	HealthCheck(ctx context.Context) error

	// Close releases any underlying resources. Idempotent: subsequent calls
	// return nil. After Close, all other methods return ErrProviderUnavailable.
	Close(ctx context.Context) error
}

// Sentinel errors for use with errors.Is.
var (
	// ErrProviderUnavailable is returned when the KMS provider is closed or
	// otherwise not operational.
	ErrProviderUnavailable = errors.New("keymanager: provider unavailable")

	// ErrKeyNotFound is returned when the referenced key ID / version does not
	// exist in the KMS.
	ErrKeyNotFound = errors.New("keymanager: key not found")

	// ErrUnwrapFailed is returned when the KMS rejects the ciphertext during
	// an UnwrapKey call (wrong key, corrupted envelope, etc.).
	ErrUnwrapFailed = errors.New("keymanager: unwrap failed")

	// ErrInvalidEnvelope is returned when the supplied KeyEnvelope is
	// structurally invalid (nil, empty ciphertext, missing fields).
	ErrInvalidEnvelope = errors.New("keymanager: invalid envelope")
)

// KeyEnvelope captures the information required to unwrap a DEK.
type KeyEnvelope struct {
	KeyID      string
	KeyVersion int
	Provider   string
	Ciphertext []byte
	// CreatedAt records when the DEK was wrapped. Zero value is safe for
	// backward-compatibility with envelopes that pre-date this field.
	CreatedAt time.Time
}

// MetaKeyVersion is stored on each object to record which wrapping key protected the DEK.
const (
	MetaKeyVersion = "x-amz-meta-encryption-key-version"
)
