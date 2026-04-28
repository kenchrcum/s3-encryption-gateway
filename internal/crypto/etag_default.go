//go:build !fips

package crypto

import (
	"crypto/md5"
	"encoding/hex"
)

// computeETag computes the ETag for the given data using MD5, which is the
// standard S3 ETag format. ETags are opaque identifiers in the S3 protocol;
// they carry no cryptographic security requirement.
func computeETag(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}
