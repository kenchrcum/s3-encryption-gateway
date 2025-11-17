package crypto

import "context"

// KeyManager abstracts external Key Management Systems (KMS) that wrap and unwrap
// per-object data encryption keys (DEKs).
//
// Implementations must never expose plaintext master keys and must ensure that all
// cryptographic operations happen within the KMS (for example via KMIP, AWS KMS, Vault Transit, etc).
//
// Current implementations:
//   - Cosmian KMIP (v0.5): Fully implemented and tested
//
// Planned implementations (v1.0):
//   - AWS KMS: Deferred due to cloud provider access requirements for testing
//   - HashiCorp Vault Transit: Deferred due to Enterprise license requirements
//
// See docs/KMS_COMPATIBILITY.md for implementation status and docs/issues/v1.0-issues.md
// for planned implementations.
type KeyManager interface {
	// Provider returns a short identifier (e.g. "cosmian-kmip") used for diagnostics and metadata.
	Provider() string

	// WrapKey encrypts the provided plaintext DEK and returns an envelope suitable for
	// persisting alongside the encrypted object metadata.
	WrapKey(ctx context.Context, plaintext []byte, metadata map[string]string) (*KeyEnvelope, error)

	// UnwrapKey decrypts the ciphertext contained in the given envelope and returns the plaintext DEK.
	UnwrapKey(ctx context.Context, envelope *KeyEnvelope, metadata map[string]string) ([]byte, error)

	// ActiveKeyVersion returns the version identifier of the primary wrapping key.
	ActiveKeyVersion(ctx context.Context) (int, error)

	// HealthCheck verifies that the KMS is accessible and operational.
	// Returns an error if the KMS is unavailable or unhealthy.
	// This should be a lightweight operation that doesn't perform actual encryption/decryption.
	HealthCheck(ctx context.Context) error

	// Close releases any underlying resources.
	Close(ctx context.Context) error
}

// KeyEnvelope captures the information required to unwrap a DEK.
type KeyEnvelope struct {
	KeyID      string
	KeyVersion int
	Provider   string
	Ciphertext []byte
}

// MetaKeyVersion is stored on each object to record which wrapping key protected the DEK.
const (
	MetaKeyVersion = "x-amz-meta-encryption-key-version"
)
