package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedDEK is a deterministic 32-byte DEK used across KAT tests.
var fixedDEK = func() []byte {
	b, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	return b
}()

// fixedIVPrefix is a deterministic 12-byte prefix.
var fixedIVPrefix = [12]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}

// fixedUploadID used across tests.
const fixedUploadID = "test-upload-id-12345"

// TestDeriveMultipartIV_KAT is a known-answer test that locks the derivation
// against accidental change. If the derivation algorithm changes, this test
// MUST fail and a CHANGELOG entry MUST accompany the update.
func TestDeriveMultipartIV_KAT(t *testing.T) {
	hash := UploadIDHash(fixedUploadID)
	iv := DeriveMultipartIV(fixedDEK, hash, fixedIVPrefix, 1, 0)

	// The expected value is computed once and locked here.
	// To regenerate: run the test with -v and update the value below.
	const expectedHex = "25676f1b3de70cfc8276d810"

	// Record the KAT value so it can be pinned.
	t.Logf("KAT IV for (part=1, chunk=0): %x", iv)

	// Length invariant is always checked.
	assert.Equal(t, 12, len(iv), "IV must always be 12 bytes")

	// If expectedHex is non-empty, enforce the known-answer.
	if expectedHex != "" {
		expected, err := hex.DecodeString(expectedHex)
		require.NoError(t, err)
		assert.Equal(t, expected, iv[:], "KAT mismatch — derivation changed without CHANGELOG entry")
	}
}

// TestDeriveMultipartIV_KAT_Stable runs a fixed derivation twice and asserts
// the result is identical (determinism requirement).
func TestDeriveMultipartIV_KAT_Stable(t *testing.T) {
	hash := UploadIDHash(fixedUploadID)
	iv1 := DeriveMultipartIV(fixedDEK, hash, fixedIVPrefix, 3, 7)
	iv2 := DeriveMultipartIV(fixedDEK, hash, fixedIVPrefix, 3, 7)
	assert.Equal(t, iv1, iv2, "derivation must be deterministic")
}

// TestDeriveMultipartIV_Uniqueness checks that every (part, chunk) combination
// in the test matrix produces a distinct 12-byte IV for a fixed DEK.
func TestDeriveMultipartIV_Uniqueness(t *testing.T) {
	hash := UploadIDHash(fixedUploadID)

	parts := []uint32{1, 2, 10000}
	chunks := []uint32{0, 1, 100, 65535}

	seen := make(map[[12]byte]struct{}, len(parts)*len(chunks))
	for _, p := range parts {
		for _, c := range chunks {
			iv := DeriveMultipartIV(fixedDEK, hash, fixedIVPrefix, p, c)
			key := iv
			_, dup := seen[key]
			assert.Falsef(t, dup, "IV collision at part=%d chunk=%d: %x", p, c, iv)
			seen[key] = struct{}{}
		}
	}
}

// TestDeriveMultipartIV_DifferentUploadID verifies that identical (part, chunk)
// tuples produce different IVs for different uploadIDs.
func TestDeriveMultipartIV_DifferentUploadID(t *testing.T) {
	hash1 := UploadIDHash("upload-aaa")
	hash2 := UploadIDHash("upload-bbb")

	iv1 := DeriveMultipartIV(fixedDEK, hash1, fixedIVPrefix, 1, 0)
	iv2 := DeriveMultipartIV(fixedDEK, hash2, fixedIVPrefix, 1, 0)

	assert.NotEqual(t, iv1, iv2, "different uploadIDs must produce different IVs for the same (part, chunk)")
}

// TestDeriveMultipartIV_Length checks the 12-byte length invariant exhaustively.
func TestDeriveMultipartIV_Length(t *testing.T) {
	hash := UploadIDHash(fixedUploadID)
	for _, p := range []uint32{1, 500, 10000} {
		for _, c := range []uint32{0, 999} {
			iv := DeriveMultipartIV(fixedDEK, hash, fixedIVPrefix, p, c)
			assert.Equal(t, mpuIVSize, len(iv), "IV length must be %d bytes", mpuIVSize)
		}
	}
}

// TestUploadIDHash verifies sha256 output size and stability.
func TestUploadIDHash(t *testing.T) {
	h := UploadIDHash("some-upload-id")
	assert.Equal(t, 32, len(h), "hash must be 32 bytes")

	h2 := UploadIDHash("some-upload-id")
	assert.Equal(t, h, h2, "hash must be deterministic")

	h3 := UploadIDHash("other-id")
	assert.NotEqual(t, h, h3, "different IDs must have different hashes")
}
