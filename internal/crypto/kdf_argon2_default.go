//go:build !fips

package crypto

import "errors"

// ErrArgon2NotEnabled is returned when argon2id is parsed from metadata but
// the gateway was not compiled with argon2id support enabled.
// Future: replace body with real argon2id implementation.
var ErrArgon2NotEnabled = errors.New("argon2id KDF is not enabled in this build")

func deriveKeyArgon2id(_ []byte, _ KDFParams) ([]byte, error) {
	return nil, ErrArgon2NotEnabled
}
