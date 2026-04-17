package crypto

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegistry_Open_UnknownProvider(t *testing.T) {
	_, err := Open(context.Background(), "nonexistent-provider-xyz", nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrProviderUnavailable))
}

func TestRegistry_Open_Memory(t *testing.T) {
	km, err := Open(context.Background(), "memory", map[string]any{})
	require.NoError(t, err)
	require.NotNil(t, km)
	require.Equal(t, "memory", km.Provider())
	_ = km.Close(context.Background())
}

func TestRegistry_Open_HSM_Stub(t *testing.T) {
	km, err := Open(context.Background(), "hsm", map[string]any{})
	require.NoError(t, err)
	require.NotNil(t, km)
	require.Equal(t, "hsm", km.Provider())
	_ = km.Close(context.Background())
}

// TestHSMStub_AllOperationsReturnUnavailable asserts the default-build HSM
// stub returns ErrProviderUnavailable for every operation. This is the
// documented behaviour when the 'hsm' build tag is absent.
func TestHSMStub_AllOperationsReturnUnavailable(t *testing.T) {
	km, err := Open(context.Background(), "hsm", map[string]any{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	_, wrapErr := km.WrapKey(context.Background(), make([]byte, 32), nil)
	require.True(t, errors.Is(wrapErr, ErrProviderUnavailable), "WrapKey: %v", wrapErr)

	_, unwrapErr := km.UnwrapKey(context.Background(), &KeyEnvelope{
		KeyID: "dummy", KeyVersion: 1, Provider: "hsm", Ciphertext: make([]byte, 24),
	}, nil)
	require.True(t, errors.Is(unwrapErr, ErrProviderUnavailable), "UnwrapKey: %v", unwrapErr)

	_, verErr := km.ActiveKeyVersion(context.Background())
	require.True(t, errors.Is(verErr, ErrProviderUnavailable), "ActiveKeyVersion: %v", verErr)

	require.True(t, errors.Is(km.HealthCheck(context.Background()), ErrProviderUnavailable))
}

func TestRegistry_Register_PanicsOnDuplicate(t *testing.T) {
	defer func() {
		r := recover()
		require.NotNil(t, r, "expected panic on duplicate registration")
	}()
	Register("memory", nil) // "memory" is already registered — should panic
}

func TestRegistry_Providers(t *testing.T) {
	names := Providers()
	require.Contains(t, names, "memory")
	require.Contains(t, names, "hsm")
}

func TestRegistry_FactoryReceivesUnchangedCfg(t *testing.T) {
	const testProvider = "test-cfg-passthrough"
	registered := false
	Register(testProvider, func(_ context.Context, cfg map[string]any) (KeyManager, error) {
		registered = true
		require.Equal(t, "bar", cfg["foo"])
		return &inMemoryKeyManager{
			providerName:  testProvider,
			keys:          map[int][]byte{1: make([]byte, 32)},
			activeVersion: 1,
		}, nil
	})
	t.Cleanup(func() {
		// Clean up registry to avoid cross-test pollution
		registryMu.Lock()
		delete(registry, testProvider)
		registryMu.Unlock()
	})

	km, err := Open(context.Background(), testProvider, map[string]any{"foo": "bar"})
	require.NoError(t, err)
	require.True(t, registered)
	_ = km.Close(context.Background())
}

func TestRegistry_Memory_MasterKeyBytes(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	km, err := Open(context.Background(), "memory", map[string]any{"master_key": key})
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	plaintext := []byte("32-byte-plaintext-dek-aaaaaaaaaa")
	env, err := km.WrapKey(context.Background(), plaintext, nil)
	require.NoError(t, err)
	got, err := km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	require.Equal(t, string(plaintext), string(got))
}

func TestRegistry_Memory_MasterKeySource_Env_Hex(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xA0 | i)
	}
	t.Setenv("TEST_MEMORY_KM_KEY", hex.EncodeToString(key))

	km, err := Open(context.Background(), "memory", map[string]any{
		"master_key_source": "env:TEST_MEMORY_KM_KEY",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })
	require.Equal(t, "memory", km.Provider())

	// Round-trip to verify the key was actually loaded.
	plaintext := []byte("abcdefghijklmnopqrstuvwxyz012345")
	env, err := km.WrapKey(context.Background(), plaintext, nil)
	require.NoError(t, err)
	got, err := km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	require.Equal(t, string(plaintext), string(got))
}

func TestRegistry_Memory_MasterKeySource_File_Hex(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x55)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "key.hex")
	require.NoError(t, os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600))

	km, err := Open(context.Background(), "memory", map[string]any{
		"master_key_source": "file:" + path,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	plaintext := []byte("file-sourced-key-roundtrip-test!")
	env, err := km.WrapKey(context.Background(), plaintext, nil)
	require.NoError(t, err)
	got, err := km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	require.Equal(t, string(plaintext), string(got))
}

func TestRegistry_Memory_MasterKeySource_Env_Missing(t *testing.T) {
	_, err := Open(context.Background(), "memory", map[string]any{
		"master_key_source": "env:DEFINITELY_NOT_SET_12345_ABC",
	})
	require.Error(t, err)
}

func TestRegistry_Memory_MasterKeySource_File_NotFound(t *testing.T) {
	_, err := Open(context.Background(), "memory", map[string]any{
		"master_key_source": "file:/nonexistent/path/definitely-not-here.bin",
	})
	require.Error(t, err)
}
