//go:build hsm

// Package crypto provides keymanager_hsm.go — the skeleton of the PKCS#11 HSM
// adapter, gated by the 'hsm' build tag.
//
// # Build requirements
//
// Compile with:
//
//	CGO_ENABLED=1 go build -tags hsm ./...
//
// A PKCS#11 shared library (e.g. SoftHSM2, AWS CloudHSM, Thales Luna, or
// nCipher) must be available at runtime. Specify the library path and slot
// configuration in the KeyManager config:
//
//	provider: hsm
//	hsm:
//	  module: /usr/lib/softhsm/libsofthsm2.so
//	  slot_id: 0
//	  pin_source: env:HSM_PIN       # or file:/run/secrets/hsm-pin
//	  wrapping_key_label: "master-wrap-key"
//	  wrapping_mechanism: CKM_AES_KEY_WRAP  # PKCS#11 mechanism OID
//
// See docs/adr/0004-hsm-adapter-contract.md for the full integration contract.
//
// # Status
//
// This file is a skeleton. All methods currently return [ErrProviderUnavailable]
// with a TODO comment marking where PKCS#11 calls should be inserted. Functional
// implementation is tracked in the v1.0 milestone.
package crypto

import (
	"context"
	"fmt"
)

// HSMConfig captures the configuration for a PKCS#11 HSM adapter.
// Fields align with the contract described in docs/adr/0004-hsm-adapter-contract.md.
type HSMConfig struct {
	// Module is the path to the PKCS#11 shared library (.so / .dll / .dylib).
	Module string

	// SlotID identifies the PKCS#11 slot to use.
	SlotID uint

	// PINSource is a secret reference of the form "env:VAR", "file:PATH", or
	// a literal PIN (not recommended for production).
	PINSource string

	// WrappingKeyLabel is the CKA_LABEL of the AES wrapping key in the HSM.
	WrappingKeyLabel string

	// WrappingMechanism is the PKCS#11 mechanism name (e.g. "CKM_AES_KEY_WRAP").
	WrappingMechanism string
}

type hsmKeyManager struct {
	cfg HSMConfig
	// TODO(hsm): add pkcs11.Ctx and session handles here
}

// NewHSMKeyManager creates a [KeyManager] backed by a PKCS#11 HSM.
//
// This constructor is a skeleton; it returns [ErrProviderUnavailable] until the
// PKCS#11 integration is implemented in v1.0.
func NewHSMKeyManager(cfg HSMConfig) (KeyManager, error) {
	// TODO(hsm): validate cfg, load PKCS#11 module, open session, find key
	return nil, fmt.Errorf("%w: HSM adapter not yet implemented — see docs/adr/0004-hsm-adapter-contract.md", ErrProviderUnavailable)
}

// Provider implements [KeyManager].
func (h *hsmKeyManager) Provider() string { return "hsm" }

// WrapKey implements [KeyManager].
func (h *hsmKeyManager) WrapKey(_ context.Context, _ []byte, _ map[string]string) (*KeyEnvelope, error) {
	// TODO(hsm): call C_EncryptInit / C_Encrypt with WrappingMechanism
	return nil, fmt.Errorf("%w: WrapKey not yet implemented", ErrProviderUnavailable)
}

// UnwrapKey implements [KeyManager].
func (h *hsmKeyManager) UnwrapKey(_ context.Context, _ *KeyEnvelope, _ map[string]string) ([]byte, error) {
	// TODO(hsm): call C_DecryptInit / C_Decrypt with WrappingMechanism
	return nil, fmt.Errorf("%w: UnwrapKey not yet implemented", ErrProviderUnavailable)
}

// ActiveKeyVersion implements [KeyManager].
func (h *hsmKeyManager) ActiveKeyVersion(_ context.Context) (int, error) {
	// TODO(hsm): query CKA_ID or CKA_LABEL version attribute
	return 0, fmt.Errorf("%w: ActiveKeyVersion not yet implemented", ErrProviderUnavailable)
}

// HealthCheck implements [KeyManager].
func (h *hsmKeyManager) HealthCheck(_ context.Context) error {
	// TODO(hsm): call C_GetSlotInfo / C_GetTokenInfo
	return fmt.Errorf("%w: HealthCheck not yet implemented", ErrProviderUnavailable)
}

// Close implements [KeyManager]. Idempotent.
func (h *hsmKeyManager) Close(_ context.Context) error {
	// TODO(hsm): C_CloseSession / C_Finalize
	return nil
}

func init() {
	Register("hsm", func(_ context.Context, cfg map[string]any) (KeyManager, error) {
		hsmCfg := HSMConfig{}
		if v, ok := cfg["module"].(string); ok {
			hsmCfg.Module = v
		}
		if v, ok := cfg["pin_source"].(string); ok {
			hsmCfg.PINSource = v
		}
		if v, ok := cfg["wrapping_key_label"].(string); ok {
			hsmCfg.WrappingKeyLabel = v
		}
		if v, ok := cfg["wrapping_mechanism"].(string); ok {
			hsmCfg.WrappingMechanism = v
		}
		return NewHSMKeyManager(hsmCfg)
	})
}
