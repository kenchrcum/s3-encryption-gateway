package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// mpuIVSize is the size of the derived IV in bytes (12 bytes for AES-GCM / ChaCha20-Poly1305).
	mpuIVSize = 12

	// mpuHKDFHashFunc is the hash function used for HKDF in multipart IV derivation.
	// SHA-256 is FIPS-approved (NIST SP 800-38D, RFC 5869).

	// MetaMPUManifest is the S3 metadata key that stores the serialised MultipartManifest
	// (inline or as a fallback pointer) on the completed object.
	MetaMPUManifest = "x-amz-meta-encryption-mpu"

	// MetaMPUEncrypted marks an object as encrypted via the MPU path.
	MetaMPUEncrypted = "x-amz-meta-encrypted-mpu"
)

// DeriveMultipartIV derives a deterministic 12-byte IV for a specific chunk
// within a specific part of an encrypted multipart upload.
//
// Derivation is:
//
//	HKDF-Expand(SHA-256, prk=DEK, salt=sha256(uploadID), info=ivPrefix || BE32(partNumber) || BE32(chunkIndex))
//
// where ivPrefix is a 12-byte random value generated at CreateMultipartUpload.
// The 12-byte output is the GCM nonce.
//
// Security properties:
//   - Unique per (DEK, uploadID, part, chunk) 4-tuple.
//   - Deterministic: retrying a failed part yields byte-identical ciphertext.
//   - Nonce reuse is impossible as long as the DEK is never reused across uploads.
func DeriveMultipartIV(dek []byte, uploadIDHash [32]byte, ivPrefix [12]byte, partNumber uint32, chunkIndex uint32) [12]byte {
	// info = ivPrefix (12 bytes) || BE32(partNumber) || BE32(chunkIndex)
	info := make([]byte, 12+4+4)
	copy(info[:12], ivPrefix[:])
	binary.BigEndian.PutUint32(info[12:16], partNumber)
	binary.BigEndian.PutUint32(info[16:20], chunkIndex)

	// Full HKDF (Extract-then-Expand) binds the derivation to the per-upload
	// salt (sha256(uploadID)). Since DEK is already a uniformly-random 256-bit
	// key, Extract is effectively a no-op wrt entropy, but salt is still used
	// as HMAC-SHA256 key during Extract — so the output is uniquely namespaced
	// per uploadID even if two uploads somehow ended up with the same DEK.
	r := hkdf.New(sha256.New, dek, uploadIDHash[:], info)

	var iv [mpuIVSize]byte
	if _, err := io.ReadFull(r, iv[:]); err != nil {
		// io.ReadFull from HKDF can only fail on malformed input; the sizes here are
		// fixed and valid, so this path is unreachable in practice. Panic to make
		// any future regression immediately visible during testing.
		panic("mpu_iv: HKDF expansion failed: " + err.Error())
	}

	return iv
}

// UploadIDHash returns sha256(uploadID) as the 32-byte salt for IV derivation.
// Stored in the Valkey state record so the gateway can reconstruct IVs during
// decryption without re-reading the uploadID from the (now-deleted) state.
func UploadIDHash(uploadID string) [32]byte {
	return sha256.Sum256([]byte(uploadID))
}
