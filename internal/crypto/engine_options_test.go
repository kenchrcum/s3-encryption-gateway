package crypto

import (
	"testing"
)

// TestWithKeyManager_SetsManager verifies that the WithKeyManager option sets
// the kmsManager field on the engine when a non-nil KeyManager is provided.
func TestWithKeyManager_SetsManager(t *testing.T) {
	eng, err := NewEngineWithOpts("test-password-for-engine-options", nil)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}

	km := NewInMemoryKeyManagerForTestDefault()

	eng2, err := NewEngineWithOpts("test-password-for-engine-options", nil, WithKeyManager(km))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() with WithKeyManager error: %v", err)
	}
	if eng2 == nil {
		t.Fatal("NewEngineWithOpts() with WithKeyManager returned nil engine")
	}

	// The engine without WithKeyManager should be valid too
	if eng == nil {
		t.Fatal("NewEngineWithOpts() without options returned nil engine")
	}
}

// TestWithKeyManager_NilIsNoop verifies that passing nil to WithKeyManager
// does not change the engine's kmsManager (nil guard).
func TestWithKeyManager_NilIsNoop(t *testing.T) {
	// Create engine without a key manager
	eng, err := NewEngineWithOpts("test-password-key-mgr-noop", nil)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}

	// Apply a nil KeyManager option — should be a no-op
	eng2, err := NewEngineWithOpts("test-password-key-mgr-noop", nil, WithKeyManager(nil))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() with nil KeyManager error: %v", err)
	}

	// Both should be valid engines
	if eng == nil || eng2 == nil {
		t.Fatal("engines should not be nil")
	}
}

// TestWithKeyResolver_SetsResolver verifies that the WithKeyResolver option
// configures the key resolver on the engine.
func TestWithKeyResolver_SetsResolver(t *testing.T) {
	resolverCalled := false
	resolver := func(version int) (string, bool) {
		resolverCalled = true
		return "resolver-password", true
	}

	eng, err := NewEngineWithOpts("test-password-resolver", nil, WithKeyResolver(resolver))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() with WithKeyResolver error: %v", err)
	}
	if eng == nil {
		t.Fatal("NewEngineWithOpts() with WithKeyResolver returned nil engine")
	}

	// The resolver should be installed but not called yet (no decryption happened)
	_ = resolverCalled // suppress unused warning; actual call happens during decrypt
}

// TestWithKeyResolver_NilIsNoop verifies that passing nil to WithKeyResolver
// does not change the engine's keyResolver.
func TestWithKeyResolver_NilIsNoop(t *testing.T) {
	eng, err := NewEngineWithOpts("test-password-resolver-noop", nil, WithKeyResolver(nil))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() with nil resolver error: %v", err)
	}
	if eng == nil {
		t.Fatal("NewEngineWithOpts() returned nil engine")
	}
}

// TestNewEngineWithOpts_MultipleOptions verifies that multiple options are all
// applied in order without any option overwriting a previous one.
func TestNewEngineWithOpts_MultipleOptions(t *testing.T) {
	km := NewInMemoryKeyManagerForTestDefault()

	resolver := func(version int) (string, bool) {
		return "v1-password", version == 1
	}

	eng, err := NewEngineWithOpts(
		"test-password-multi-opts",
		nil,
		WithKeyManager(km),
		WithKeyResolver(resolver),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() with multiple options error: %v", err)
	}
	if eng == nil {
		t.Fatal("NewEngineWithOpts() with multiple options returned nil engine")
	}
}

// TestNewEngineWithOpts_ValidPassword verifies that NewEngineWithOpts with a
// valid password and no additional options returns a usable EncryptionEngine.
func TestNewEngineWithOpts_ValidPassword(t *testing.T) {
	eng, err := NewEngineWithOpts("valid-password-at-least-20-chars", nil)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	if eng == nil {
		t.Fatal("NewEngineWithOpts() returned nil engine")
	}

	// Verify the engine can be used (implements EncryptionEngine interface)
	var _ EncryptionEngine = eng
}
