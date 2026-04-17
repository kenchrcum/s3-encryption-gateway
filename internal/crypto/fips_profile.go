//go:build fips

package crypto

import (
	"crypto/fips140"
	"fmt"
)

// FIPSEnabled reports whether the binary was built and is running with the
// FIPS 140-3 profile active. It delegates to crypto/fips140.Enabled() when
// the binary is built with -tags=fips.
func FIPSEnabled() bool {
	return fips140.Enabled()
}

// AssertFIPS returns an error if the binary was built with -tags=fips but
// the runtime FIPS module is not active. This is called at startup to ensure
// that the FIPS 140-3 module has been properly initialized and power-on
// self-tests have passed. If the environment does not have GOFIPS140=on,
// the program should fail closed.
func AssertFIPS() error {
	if !fips140.Enabled() {
		return fmt.Errorf("FIPS 140-3 profile requested but runtime module is not active; " +
			"ensure GOFIPS140=v1.0.0 is set in the environment and the binary was built with -tags=fips")
	}
	return nil
}
