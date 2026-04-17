//go:build hsm

package crypto

import (
	"context"
	"errors"
	"testing"
)

// TestHSMKeyManager_Conformance runs the full conformance suite against the
// HSM adapter. It is only compiled when the 'hsm' build tag is set.
//
// Without a real HSM, every operation returns ErrProviderUnavailable, so the
// test skips itself gracefully in that case.
func TestHSMKeyManager_Conformance(t *testing.T) {
	t.Skip("HSM adapter is a skeleton — functional tests require a real PKCS#11 device")

	ConformanceSuite(t, func(t *testing.T) KeyManager {
		km, err := NewHSMKeyManager(HSMConfig{
			Module:            "/usr/lib/softhsm/libsofthsm2.so",
			SlotID:            0,
			PINSource:         "env:HSM_PIN",
			WrappingKeyLabel:  "master-wrap-key",
			WrappingMechanism: "CKM_AES_KEY_WRAP",
		})
		if err != nil {
			if errors.Is(err, ErrProviderUnavailable) {
				t.Skip("HSM not available:", err)
			}
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = km.Close(context.Background()) })
		return km
	})
}
