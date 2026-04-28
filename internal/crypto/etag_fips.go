//go:build fips

package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

// computeETag computes the ETag for the given data using SHA-256 in FIPS mode.
// MD5 is avoided in FIPS-approved builds; SHA-256 is used as a functionally
// equivalent opaque identifier. S3 clients treat ETags as opaque strings and
// do not require a specific hash algorithm.
func computeETag(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
