package crypto

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
)

// KMIPKeyReference describes a wrapping key managed by an external KMIP service.
type KMIPKeyReference struct {
	ID      string
	Version int
}

// CosmianKMIPOptions encapsulates the configuration required to connect to a KMIP-compatible KMS.
type CosmianKMIPOptions struct {
	Endpoint       string
	Keys           []KMIPKeyReference
	TLSConfig      *tls.Config
	Timeout        time.Duration
	Provider       string
	DualReadWindow int
}

type cosmianKeyState struct {
	opts          CosmianKMIPOptions
	keyLookup     map[string]KMIPKeyReference
	versionLookup map[int]KMIPKeyReference
	timeout       time.Duration
}

type cosmianKMIPManager struct {
	client *kmipclient.Client
	state  *cosmianKeyState
	mu     sync.RWMutex
}

// NewCosmianKMIPManager creates a KMIP-backed KeyManager implementation.
func NewCosmianKMIPManager(opts CosmianKMIPOptions) (KeyManager, error) {
	state, err := prepareCosmianKeyState(opts)
	if err != nil {
		return nil, err
	}

	if endpointHasScheme(state.opts.Endpoint) {
		return newCosmianKMIPJSONManager(state)
	}

	return newCosmianKMIPBinaryManager(state)
}

func prepareCosmianKeyState(opts CosmianKMIPOptions) (*cosmianKeyState, error) {
	opts.Endpoint = strings.TrimSpace(opts.Endpoint)
	if opts.Endpoint == "" {
		return nil, errors.New("kms: endpoint is required")
	}

	if len(opts.Keys) == 0 {
		return nil, errors.New("kms: at least one wrapping key reference is required")
	}

	keys := make([]KMIPKeyReference, len(opts.Keys))
	for i := range opts.Keys {
		if opts.Keys[i].ID == "" {
			return nil, fmt.Errorf("kms: key reference at index %d missing id", i)
		}
		keys[i] = opts.Keys[i]
		if keys[i].Version == 0 {
			keys[i].Version = i + 1
		}
	}

	provider := opts.Provider
	if provider == "" {
		provider = "cosmian-kmip"
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	tlsCfg := opts.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsCfg = tlsCfg.Clone()
	}

	keyLookup := make(map[string]KMIPKeyReference, len(keys))
	versionLookup := make(map[int]KMIPKeyReference, len(keys))
	for _, ref := range keys {
		keyLookup[ref.ID] = ref
		versionLookup[ref.Version] = ref
	}

	return &cosmianKeyState{
		opts: CosmianKMIPOptions{
			Endpoint:       opts.Endpoint,
			Keys:           slices.Clone(keys),
			TLSConfig:      tlsCfg,
			Timeout:        timeout,
			Provider:       provider,
			DualReadWindow: opts.DualReadWindow,
		},
		keyLookup:     keyLookup,
		versionLookup: versionLookup,
		timeout:       timeout,
	}, nil
}

func newCosmianKMIPBinaryManager(state *cosmianKeyState) (KeyManager, error) {
	client, err := kmipclient.Dial(state.opts.Endpoint, kmipclient.WithTlsConfig(state.opts.TLSConfig))
	if err != nil {
		return nil, fmt.Errorf("kms: failed to dial KMIP endpoint %s: %w", state.opts.Endpoint, err)
	}
	return &cosmianKMIPManager{
		client: client,
		state:  state,
	}, nil
}

// Provider implements KeyManager.
func (m *cosmianKMIPManager) Provider() string {
	return m.state.opts.Provider
}

// WrapKey implements KeyManager.
func (m *cosmianKMIPManager) WrapKey(ctx context.Context, plaintext []byte, _ map[string]string) (*KeyEnvelope, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("kms: plaintext DEK is empty")
	}
	ctx, cancel := m.state.withTimeout(ctx)
	defer cancel()
	active := m.state.opts.Keys[0]

	resp, err := m.client.
		Encrypt(active.ID).
		WithCryptographicParameters(m.defaultCryptoParams()).
		Data(plaintext).
		ExecContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms: encrypt failed (key ID: %s): %w", active.ID, err)
	}

	keyID := resp.UniqueIdentifier
	if keyID == "" {
		keyID = active.ID
	}
	version := active.Version
	if ref, ok := m.state.keyLookup[keyID]; ok {
		version = ref.Version
	}

	return &KeyEnvelope{
		KeyID:      keyID,
		KeyVersion: version,
		Provider:   m.Provider(),
		Ciphertext: resp.Data,
	}, nil
}

// UnwrapKey implements KeyManager.
func (m *cosmianKMIPManager) UnwrapKey(ctx context.Context, envelope *KeyEnvelope, _ map[string]string) ([]byte, error) {
	if envelope == nil {
		return nil, errors.New("kms: key envelope is nil")
	}
	if len(envelope.Ciphertext) == 0 {
		return nil, errors.New("kms: wrapped key is empty")
	}
	ctx, cancel := m.state.withTimeout(ctx)
	defer cancel()

	candidates := m.state.candidateKeys(envelope)
	if len(candidates) == 0 {
		return nil, errors.New("kms: no key candidates available for unwrap")
	}

	var lastErr error
	attempts := 0
	maxAttempts := m.state.opts.DualReadWindow + 1
	if maxAttempts <= 0 {
		maxAttempts = len(candidates) // Try all if DualReadWindow is 0 or negative
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if attempts >= maxAttempts {
			break
		}
		resp, err := m.client.
			Decrypt(candidate).
			WithCryptographicParameters(m.defaultCryptoParams()).
			Data(envelope.Ciphertext).
			ExecContext(ctx)
		if err == nil {
			return resp.Data, nil
		}
		lastErr = err
		attempts++
	}

	if lastErr == nil {
		lastErr = errors.New("kms: unwrap failed with no attempts recorded")
	}
	return nil, fmt.Errorf("kms: decrypt failed: %w", lastErr)
}

// ActiveKeyVersion implements KeyManager.
func (m *cosmianKMIPManager) ActiveKeyVersion(_ context.Context) (int, error) {
	if len(m.state.opts.Keys) == 0 {
		return 0, errors.New("kms: no keys configured")
	}
	return m.state.opts.Keys[0].Version, nil
}

// HealthCheck implements KeyManager.
func (m *cosmianKMIPManager) HealthCheck(ctx context.Context) error {
	if m.client == nil {
		return errors.New("kms: client not initialized")
	}
	if len(m.state.opts.Keys) == 0 {
		return errors.New("kms: no keys configured")
	}

	ctx, cancel := m.state.withTimeout(ctx)
	defer cancel()

	// Perform a lightweight Get operation on the first key to verify connectivity
	// This doesn't perform encryption/decryption, just verifies the KMS is reachable
	active := m.state.opts.Keys[0]
	_, err := m.client.Get(active.ID).ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("kms: health check failed (key ID: %s): %w", active.ID, err)
	}
	return nil
}

// Close implements KeyManager.
func (m *cosmianKMIPManager) Close(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client != nil {
		err := m.client.Close()
		m.client = nil
		return err
	}
	return nil
}

func (m *cosmianKMIPManager) defaultCryptoParams() kmip.CryptographicParameters {
	// Cosmian KMS may not support NISTKeyWrap mode explicitly.
	// Try without BlockCipherMode first, or use a standard mode.
	// For key wrapping, we can omit the mode and let the server choose,
	// or use ECB mode which is common for key wrapping.
	return kmip.CryptographicParameters{
		CryptographicAlgorithm: kmip.CryptographicAlgorithmAES,
		// Don't specify BlockCipherMode - let Cosmian KMS choose the appropriate mode
		// BlockCipherMode is optional for Encrypt/Decrypt operations
		PaddingMethod: kmip.PaddingMethodNone,
	}
}

func (s *cosmianKeyState) candidateKeys(env *KeyEnvelope) []string {
	result := make([]string, 0, len(s.opts.Keys))
	seen := make(map[string]struct{})

	id := env.KeyID
	if id == "" && env.KeyVersion != 0 {
		if ref, ok := s.versionLookup[env.KeyVersion]; ok {
			id = ref.ID
		}
	}
	if id != "" {
		result = append(result, id)
		seen[id] = struct{}{}
	}

	for _, ref := range s.opts.Keys {
		if _, ok := seen[ref.ID]; ok {
			continue
		}
		result = append(result, ref.ID)
		seen[ref.ID] = struct{}{}
	}
	return result
}

func (s *cosmianKeyState) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, s.timeout)
}

func endpointHasScheme(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	if strings.Contains(endpoint, "://") {
		u, err := url.Parse(endpoint)
		return err == nil && u.Scheme != ""
	}
	return false
}
