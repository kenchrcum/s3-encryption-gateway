//go:build fips

package crypto

func deriveKeyArgon2id(_ []byte, _ KDFParams) ([]byte, error) {
	return nil, ErrAlgorithmNotApproved
}
