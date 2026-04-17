//go:build !hsm

// Package crypto provides keymanager_hsm_stub.go — the default (non-HSM) build
// of the HSM adapter. All methods return ErrProviderUnavailable with a clear
// message pointing operators to the documentation.
//
// To build with real HSM support compile with -tags hsm and ensure that the
// cgo PKCS#11 dependencies described in docs/adr/0004-hsm-adapter-contract.md
// are satisfied.
package crypto

import (
	"context"
	"fmt"
)

type hsmKeyManagerStub struct{}

// Provider implements [KeyManager].
func (h *hsmKeyManagerStub) Provider() string { return "hsm" }

// WrapKey implements [KeyManager]. Always returns [ErrProviderUnavailable].
func (h *hsmKeyManagerStub) WrapKey(_ context.Context, _ []byte, _ map[string]string) (*KeyEnvelope, error) {
	return nil, fmt.Errorf("%w: HSM adapter requires the 'hsm' build tag and PKCS#11 dependencies — see docs/adr/0004-hsm-adapter-contract.md", ErrProviderUnavailable)
}

// UnwrapKey implements [KeyManager]. Always returns [ErrProviderUnavailable].
func (h *hsmKeyManagerStub) UnwrapKey(_ context.Context, _ *KeyEnvelope, _ map[string]string) ([]byte, error) {
	return nil, fmt.Errorf("%w: HSM adapter requires the 'hsm' build tag and PKCS#11 dependencies — see docs/adr/0004-hsm-adapter-contract.md", ErrProviderUnavailable)
}

// ActiveKeyVersion implements [KeyManager]. Always returns [ErrProviderUnavailable].
func (h *hsmKeyManagerStub) ActiveKeyVersion(_ context.Context) (int, error) {
	return 0, fmt.Errorf("%w: HSM adapter requires the 'hsm' build tag", ErrProviderUnavailable)
}

// HealthCheck implements [KeyManager]. Always returns [ErrProviderUnavailable].
func (h *hsmKeyManagerStub) HealthCheck(_ context.Context) error {
	return fmt.Errorf("%w: HSM adapter requires the 'hsm' build tag", ErrProviderUnavailable)
}

// Close implements [KeyManager]. Idempotent; returns nil.
func (h *hsmKeyManagerStub) Close(_ context.Context) error { return nil }

func init() {
	Register("hsm", func(_ context.Context, _ map[string]any) (KeyManager, error) {
		return &hsmKeyManagerStub{}, nil
	})
}
