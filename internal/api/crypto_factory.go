package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/sirupsen/logrus"
)

func init() {
	// Register the "cosmian" / "kmip" adapter here — not in the crypto package —
	// so that the KMIP client dependency is only pulled in when the api package
	// is compiled, keeping internal/crypto tests dependency-light.
	crypto.Register("cosmian", cosmianFactory)
	crypto.Register("kmip", cosmianFactory) // alias
}

// cosmianFactory is the adapter Factory for the Cosmian KMIP provider.
//
// It expects cfg["__opts"] to hold a pre-built crypto.CosmianKMIPOptions
// struct. In practice BuildKeyManager builds this struct from the typed
// configuration and passes it to crypto.Open via this factory. Third-party
// callers of crypto.Open("cosmian", …) must likewise supply a constructed
// options struct under the "__opts" key.
func cosmianFactory(_ context.Context, cfg map[string]any) (crypto.KeyManager, error) {
	opts, ok := cfg["__opts"].(crypto.CosmianKMIPOptions)
	if !ok {
		return nil, fmt.Errorf("cosmian factory: missing __opts (crypto.CosmianKMIPOptions) in configuration map")
	}
	return crypto.NewCosmianKMIPManager(opts)
}

// BuildKeyManager builds a KeyManager from configuration.
//
// For providers "cosmian" and "kmip" it builds the typed options struct and
// calls the registered factory; for "memory" and "hsm" it delegates directly
// to the registry via [crypto.Open].
func BuildKeyManager(cfg *config.KeyManagerConfig, logger *logrus.Logger) (crypto.KeyManager, error) {
	_ = logger // reserved for future structured logging
	provider := strings.ToLower(cfg.Provider)
	if provider == "" {
		provider = "cosmian"
	}

	switch provider {
	case "cosmian", "kmip":
		opts, err := buildCosmianOptions(cfg)
		if err != nil {
			return nil, err
		}
		return crypto.Open(context.Background(), provider, map[string]any{"__opts": opts})
	case "memory":
		memoryCfg := map[string]any{}
		if src := cfg.Memory.MasterKeySource; src != "" {
			memoryCfg["master_key_source"] = src
		}
		return crypto.Open(context.Background(), "memory", memoryCfg)
	case "hsm":
		return crypto.Open(context.Background(), "hsm", map[string]any{})
	default:
		// Attempt generic registry lookup for third-party adapters.
		km, err := crypto.Open(context.Background(), provider, map[string]any{})
		if err != nil {
			return nil, fmt.Errorf("unsupported key manager provider %q: %w", provider, err)
		}
		return km, nil
	}
}

// buildCosmianOptions constructs a crypto.CosmianKMIPOptions struct from the
// typed configuration. It performs the same validation as the previous
// newCosmianKeyManager helper.
func buildCosmianOptions(kmCfg *config.KeyManagerConfig) (crypto.CosmianKMIPOptions, error) {
	if kmCfg.Cosmian.Endpoint == "" {
		return crypto.CosmianKMIPOptions{}, fmt.Errorf("cosmian.key_manager.endpoint is required")
	}
	if len(kmCfg.Cosmian.Keys) == 0 {
		return crypto.CosmianKMIPOptions{}, fmt.Errorf("cosmian.key_manager.keys must include at least one wrapping key reference")
	}

	tlsCfg, err := buildCosmianTLSConfig(kmCfg.Cosmian)
	if err != nil {
		return crypto.CosmianKMIPOptions{}, err
	}

	keyRefs := make([]crypto.KMIPKeyReference, 0, len(kmCfg.Cosmian.Keys))
	for i, key := range kmCfg.Cosmian.Keys {
		if key.ID == "" {
			return crypto.CosmianKMIPOptions{}, fmt.Errorf("cosmian.key_manager.keys[%d].id is required", i)
		}
		version := key.Version
		if version == 0 {
			version = i + 1
		}
		keyRefs = append(keyRefs, crypto.KMIPKeyReference{ID: key.ID, Version: version})
	}

	return crypto.CosmianKMIPOptions{
		Endpoint:       kmCfg.Cosmian.Endpoint,
		Keys:           keyRefs,
		TLSConfig:      tlsCfg,
		Timeout:        kmCfg.Cosmian.Timeout,
		Provider:       "cosmian-kmip",
		DualReadWindow: kmCfg.DualReadWindow,
	}, nil
}

func buildCosmianTLSConfig(cfg config.CosmianConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // operator opt-in
	}

	if cfg.CACert != "" {
		caData, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read Cosmian CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("failed to parse Cosmian CA certificate")
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load Cosmian client certificate: %w", err)
		}
		tlsCfg.Certificates = append(tlsCfg.Certificates, cert)
	}

	return tlsCfg, nil
}
