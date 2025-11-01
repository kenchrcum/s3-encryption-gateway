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
