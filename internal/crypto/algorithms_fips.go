//go:build fips

package crypto

// DefaultAlgorithmConfig returns the default algorithm configuration for FIPS mode.
// In FIPS builds, only AES-256-GCM (FIPS 140-3 approved) is available.
// ChaCha20-Poly1305 is excluded as it is not on the FIPS-approved list.
func DefaultAlgorithmConfig() AlgorithmConfig {
	return AlgorithmConfig{
		PreferredAlgorithm: AlgorithmAES256GCM,
		SupportedAlgorithms: []string{
			AlgorithmAES256GCM,
		},
	}
}
