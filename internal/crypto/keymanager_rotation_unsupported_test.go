//go:build !hsm

package crypto

import (
	"context"
	"testing"
)

// TestHSMStub_DoesNotImplementRotatableKeyManager verifies the intentional
// contract documented in ADR 0007: the default (non-cgo) HSM stub does NOT
// implement RotatableKeyManager. Admin rotation handlers rely on this to
// return 501 NotImplemented when an operator attempts rotation against a
// non-functional HSM adapter.
func TestHSMStub_DoesNotImplementRotatableKeyManager(t *testing.T) {
	km, err := Open(context.Background(), "hsm", nil)
	if err != nil {
		t.Fatalf("Open(hsm): %v", err)
	}
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	if _, ok := km.(RotatableKeyManager); ok {
		t.Fatal("HSM stub unexpectedly implements RotatableKeyManager — this would allow admin rotation on a non-functional adapter")
	}
}
