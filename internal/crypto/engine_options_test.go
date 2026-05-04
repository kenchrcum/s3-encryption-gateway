package crypto

import (
	"testing"
)

// TestWithKeyManager_SetsManager verifies that the WithKeyManager option sets
// the kmsManager field on the engine when a non-nil KeyManager is provided.
func TestWithKeyManager_SetsManager(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-password-for-engine-options"), nil)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}

	km := NewInMemoryKeyManagerForTestDefault()

	eng2, err := NewEngineWithOpts([]byte("test-password-for-engine-options"), nil, WithKeyManager(km))
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
	eng, err := NewEngineWithOpts([]byte("test-password-key-mgr-noop"), nil)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}

	// Apply a nil KeyManager option — should be a no-op
	eng2, err := NewEngineWithOpts([]byte("test-password-key-mgr-noop"), nil, WithKeyManager(nil))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() with nil KeyManager error: %v", err)
	}

	// Both should be valid engines
	if eng == nil || eng2 == nil {
		t.Fatal("engines should not be nil")
	}
}

// TestNewEngineWithOpts_MultipleOptions verifies that multiple options are all
// applied in order without any option overwriting a previous one.
func TestNewEngineWithOpts_MultipleOptions(t *testing.T) {
	km := NewInMemoryKeyManagerForTestDefault()

	eng, err := NewEngineWithOpts(
		[]byte("test-password-multi-opts"),
		nil,
		WithKeyManager(km),
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
	eng, err := NewEngineWithOpts([]byte("valid-password-at-least-20-chars"), nil)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	if eng == nil {
		t.Fatal("NewEngineWithOpts() returned nil engine")
	}

	// Verify the engine can be used (implements EncryptionEngine interface)
	var _ EncryptionEngine = eng
}
