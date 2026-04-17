//go:build !fips

package crypto

// FIPSEnabled reports whether the binary was built and is running with the
// FIPS 140-3 profile active. It is always false in non-fips builds.
func FIPSEnabled() bool {
	return false
}

// AssertFIPS returns an error if the binary was built with -tags=fips but
// the runtime FIPS module is not active. In non-FIPS builds, it succeeds trivially.
func AssertFIPS() error {
	return nil
}
