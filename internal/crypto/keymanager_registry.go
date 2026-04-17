package crypto

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Factory creates a [KeyManager] from a provider-specific configuration map.
// The cfg map contains string keys whose meaning is defined by each adapter.
// Factories MUST be safe for concurrent use.
type Factory func(ctx context.Context, cfg map[string]any) (KeyManager, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{}
)

// Register registers a [Factory] under the given name. It panics if the name
// has already been registered, following the convention established by
// [database/sql].
//
// Adapters should call Register from an init() function in their own package:
//
//	func init() {
//	    crypto.Register("myadapter", myAdapterFactory)
//	}
//
// See docs/KMS_COMPATIBILITY.md for the full list of built-in adapter names.
func Register(name string, f Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("keymanager: Register called twice for provider %q", name))
	}
	registry[name] = f
}

// Open opens a [KeyManager] by name, passing cfg to the factory function.
// Returns [ErrProviderUnavailable] if no factory has been registered under name.
func Open(ctx context.Context, name string, cfg map[string]any) (KeyManager, error) {
	registryMu.RLock()
	f, ok := registry[name]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: unknown provider %q", ErrProviderUnavailable, name)
	}
	return f(ctx, cfg)
}

// Providers returns the list of registered provider names in sorted order.
// Useful for diagnostics and documentation.
func Providers() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}

// init registers the pure-Go adapters that ship with this package.
// The "cosmian" adapter is registered from internal/api/crypto_factory.go
// to avoid pulling the KMIP client dependency into the crypto package's tests.
func init() {
	Register("memory", memoryFactory)
	// "hsm" is registered by keymanager_hsm_stub.go (default build)
	// or keymanager_hsm.go (build tag: hsm).
}

// memoryFactory builds an in-memory KeyManager from a configuration map.
//
// Recognised keys (all optional):
//
//   - "master_key"         []byte or string: raw master key bytes.
//   - "master_key_source"  string: secret reference for the master key:
//     "env:VAR"   — read from environment variable VAR (hex or raw UTF-8).
//     "file:PATH" — read from file at PATH (hex if entire content is valid
//     hex and length ∈ {32, 48, 64}, otherwise raw bytes).
//     literal     — interpreted as raw UTF-8 bytes (not recommended).
//   - "provider"           string: override the KeyManager.Provider() string.
//
// If both "master_key" and "master_key_source" are present, "master_key"
// wins. If neither is present, a fresh 32-byte key is generated (suitable
// for tests only — keys are lost on process exit).
func memoryFactory(_ context.Context, cfg map[string]any) (KeyManager, error) {
	var masterKey []byte

	if raw, ok := cfg["master_key"]; ok {
		switch v := raw.(type) {
		case []byte:
			masterKey = v
		case string:
			masterKey = []byte(v)
		}
	}

	if len(masterKey) == 0 {
		if src, ok := cfg["master_key_source"].(string); ok && src != "" {
			resolved, err := resolveMemoryMasterKey(src)
			if err != nil {
				return nil, err
			}
			masterKey = resolved
		}
	}

	var opts []MemoryOption
	if p, ok := cfg["provider"].(string); ok && p != "" {
		opts = append(opts, WithMemoryProvider(p))
	}
	return NewInMemoryKeyManager(masterKey, opts...)
}

// resolveMemoryMasterKey resolves a master-key secret reference into raw bytes.
func resolveMemoryMasterKey(src string) ([]byte, error) {
	switch {
	case strings.HasPrefix(src, "env:"):
		name := strings.TrimPrefix(src, "env:")
		val := os.Getenv(name)
		if val == "" {
			return nil, fmt.Errorf("keymanager/memory: environment variable %q is empty or unset", name)
		}
		return decodeMemoryKeyMaterial(val), nil
	case strings.HasPrefix(src, "file:"):
		path := strings.TrimPrefix(src, "file:")
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("keymanager/memory: failed to read master key file %q: %w", path, err)
		}
		trimmed := strings.TrimSpace(string(data))
		if trimmed == "" {
			return nil, fmt.Errorf("keymanager/memory: master key file %q is empty", path)
		}
		return decodeMemoryKeyMaterial(trimmed), nil
	default:
		// Treat as a literal value (raw bytes, or hex if it parses cleanly).
		return decodeMemoryKeyMaterial(src), nil
	}
}

// decodeMemoryKeyMaterial tries hex decoding first (for 16/24/32-byte AES keys
// expressed as 32/48/64 hex chars); otherwise returns the raw UTF-8 bytes.
func decodeMemoryKeyMaterial(s string) []byte {
	s = strings.TrimSpace(s)
	if l := len(s); l == 32 || l == 48 || l == 64 {
		if decoded, err := hex.DecodeString(s); err == nil {
			return decoded
		}
	}
	return []byte(s)
}
