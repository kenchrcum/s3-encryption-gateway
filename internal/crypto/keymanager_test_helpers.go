package crypto

import (
	"context"
	"crypto/rand"
)

// InMemoryKeyManagerForTest is a type alias exposing the inMemoryKeyManager
// for use in tests outside the crypto package. It is only intended for
// integration and admin-rotation tests.
type InMemoryKeyManagerForTest = inMemoryKeyManager

// NewInMemoryKeyManagerForTestWithKeys creates an in-memory KeyManager with
// the given master key material at the specified version. The returned value
// satisfies both KeyManager and RotatableKeyManager.
func NewInMemoryKeyManagerForTestWithKeys(masterKey []byte, version int) *inMemoryKeyManager {
	if len(masterKey) != 32 {
		panic("master key must be 32 bytes")
	}
	keyCopy := make([]byte, 32)
	copy(keyCopy, masterKey)

	km := &inMemoryKeyManager{
		keys:          make(map[int][]byte),
		activeVersion: version,
		providerName:  "memory",
	}
	km.keys[version] = keyCopy
	return km
}

// NewInMemoryKeyManagerForTestDefault creates an in-memory KeyManager with
// a random 32-byte key at version 1. Useful for simple test fixtures.
func NewInMemoryKeyManagerForTestDefault() *inMemoryKeyManager {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("failed to generate random key: " + err.Error())
	}
	return NewInMemoryKeyManagerForTestWithKeys(key, 1)
}

// AddVersionForTest stages a new version on an inMemoryKeyManager for testing.
func AddVersionForTest(km KeyManager, version int, material []byte) error {
	if m, ok := km.(*inMemoryKeyManager); ok {
		return m.AddVersion(context.Background(), version, material)
	}
	return ErrRotationNotSupported
}
