//go:build !fips

package crypto

// DefaultAlgorithmConfig returns the default algorithm configuration.
// In non-FIPS builds, both AES-256-GCM and ChaCha20-Poly1305 are available.
func DefaultAlgorithmConfig() AlgorithmConfig {
	return AlgorithmConfig{
		PreferredAlgorithm: AlgorithmAES256GCM,
		SupportedAlgorithms: []string{
			AlgorithmAES256GCM,
			AlgorithmChaCha20Poly1305,
		},
	}
}
