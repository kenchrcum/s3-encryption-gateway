package crypto

import (
	"encoding/base64"
	"fmt"
)

// encodeBase64 encodes a byte slice to base64 string.
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// decodeBase64 decodes a base64 string to byte slice.
func decodeBase64(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 string: %w", err)
	}
	return data, nil
}

// DecodeBase64Loose decodes a base64 or base64url string (exported for api package).
func DecodeBase64Loose(s string) ([]byte, error) {
	// Try standard base64 first, then url-safe.
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(s)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid base64 string: %w", err)
	}
	return b, nil
}

// ZeroBytes overwrites b with zeros (exported for api package cleanup of DEKs).
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
