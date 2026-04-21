package crypto

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPassword = "a-sufficiently-long-test-password"

func TestPasswordKeyManager_WrapUnwrap_RoundTrip(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword)
	require.NoError(t, err)

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}

	ctx := context.Background()
	env, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)
	assert.Equal(t, passwordKMProvider, env.Provider)
	assert.NotEmpty(t, env.Ciphertext)
	assert.Equal(t, 1, env.KeyVersion)

	// Ciphertext must not contain the plaintext DEK.
	for i := 0; i+len(dek) <= len(env.Ciphertext); i++ {
		assert.NotEqual(t, dek, env.Ciphertext[i:i+len(dek)], "ciphertext must not embed plaintext DEK at offset %d", i)
	}

	got, err := km.UnwrapKey(ctx, env, nil)
	require.NoError(t, err)
	assert.Equal(t, dek, got)
}

// TestPasswordKeyManager_DifferentSaltPerWrap verifies two wraps of the same
// DEK produce different ciphertexts (random salt per wrap).
func TestPasswordKeyManager_DifferentSaltPerWrap(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword)
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()

	env1, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)
	env2, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	assert.NotEqual(t, env1.Ciphertext, env2.Ciphertext, "two wraps must produce distinct ciphertexts")
}

// TestPasswordKeyManager_WrongPassword verifies that a different password
// cannot unwrap the envelope.
func TestPasswordKeyManager_WrongPassword(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword)
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()
	env, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	km2, err := NewPasswordKeyManager("totally-different-password!!")
	require.NoError(t, err)
	_, err = km2.UnwrapKey(ctx, env, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnwrapFailed)
}

// TestPasswordKeyManager_TamperedCiphertext verifies authentication failure
// when the ciphertext is modified.
func TestPasswordKeyManager_TamperedCiphertext(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword)
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()
	env, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	tampered := make([]byte, len(env.Ciphertext))
	copy(tampered, env.Ciphertext)
	tampered[len(tampered)-1] ^= 0xff
	env.Ciphertext = tampered

	_, err = km.UnwrapKey(ctx, env, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnwrapFailed)
}

// TestPasswordKeyManager_ProviderMismatch verifies rejection of foreign envelopes.
func TestPasswordKeyManager_ProviderMismatch(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword)
	require.NoError(t, err)

	env := &KeyEnvelope{Provider: "cosmian-kmip", Ciphertext: []byte{1, 2, 3}}
	_, err = km.UnwrapKey(context.Background(), env, nil)
	require.Error(t, err)
}

// TestPasswordKeyManager_InvalidEnvelope verifies ErrInvalidEnvelope on nil/empty.
func TestPasswordKeyManager_InvalidEnvelope(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword)
	require.NoError(t, err)
	ctx := context.Background()

	_, err = km.UnwrapKey(ctx, nil, nil)
	assert.ErrorIs(t, err, ErrInvalidEnvelope)

	_, err = km.UnwrapKey(ctx, &KeyEnvelope{Provider: passwordKMProvider}, nil)
	assert.ErrorIs(t, err, ErrInvalidEnvelope)
}

// TestPasswordKeyManager_ShortPassword verifies rejection of short passwords.
func TestPasswordKeyManager_ShortPassword(t *testing.T) {
	_, err := NewPasswordKeyManager("short")
	require.Error(t, err)
}

// TestPasswordKeyManager_HealthCheck verifies HealthCheck passes while open.
func TestPasswordKeyManager_HealthCheck(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword)
	require.NoError(t, err)
	assert.NoError(t, km.HealthCheck(context.Background()))

	km.Close(context.Background())
	assert.ErrorIs(t, km.HealthCheck(context.Background()), ErrProviderUnavailable)
}

// TestPasswordKeyManager_ClosedRejectsAllOps verifies the closed state.
func TestPasswordKeyManager_ClosedRejectsAllOps(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword)
	require.NoError(t, err)
	km.Close(context.Background())

	ctx := context.Background()
	_, err = km.WrapKey(ctx, make([]byte, 32), nil)
	assert.ErrorIs(t, err, ErrProviderUnavailable)

	_, err = km.ActiveKeyVersion(ctx)
	assert.ErrorIs(t, err, ErrProviderUnavailable)
}

// TestIsPasswordKeyManager confirms the type predicate.
func TestIsPasswordKeyManager(t *testing.T) {
	km, _ := NewPasswordKeyManager(testPassword)
	assert.True(t, IsPasswordKeyManager(km))
	assert.False(t, IsPasswordKeyManager(nil))
}
