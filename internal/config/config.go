package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// Config holds the complete application configuration.
type Config struct {
	ListenAddr    string            `yaml:"listen_addr" env:"LISTEN_ADDR"`
	LogLevel      string            `yaml:"log_level" env:"LOG_LEVEL"`
	ProxiedBucket string            `yaml:"proxied_bucket" env:"PROXIED_BUCKET"` // If set, only this bucket will be accessible
	Backend       BackendConfig     `yaml:"backend"`
	Encryption    EncryptionConfig  `yaml:"encryption"`
	Compression   CompressionConfig `yaml:"compression"`
	Cache         CacheConfig       `yaml:"cache"`
	Audit         AuditConfig       `yaml:"audit"`
	TLS           TLSConfig         `yaml:"tls"`
	Server        ServerConfig      `yaml:"server"`
	RateLimit     RateLimitConfig   `yaml:"rate_limit"`
	Tracing       TracingConfig     `yaml:"tracing"`
	Metrics       MetricsConfig     `yaml:"metrics"`
	Logging       LoggingConfig     `yaml:"logging"`
	Admin          AdminConfig          `yaml:"admin"`
	PolicyFiles    []string             `yaml:"policies" env:"POLICIES"`
	MultipartState MultipartStateConfig `yaml:"multipart_state"`
}

// BackendConfig holds S3 backend configuration.
type BackendConfig struct {
	Endpoint     string `yaml:"endpoint" env:"BACKEND_ENDPOINT"`
	Region       string `yaml:"region" env:"BACKEND_REGION"`
	AccessKey    string `yaml:"access_key" env:"BACKEND_ACCESS_KEY"`
	SecretKey    string `yaml:"secret_key" env:"BACKEND_SECRET_KEY"`
	Provider     string `yaml:"provider" env:"BACKEND_PROVIDER"` // aws, wasabi, hetzner, minio, digitalocean, backblaze, cloudflare, linode, scaleway, oracle, idrive
	UseSSL       bool   `yaml:"use_ssl" env:"BACKEND_USE_SSL"`
	UsePathStyle bool   `yaml:"use_path_style" env:"BACKEND_USE_PATH_STYLE"`
	// Compatibility options for backends with metadata restrictions
	FilterMetadataKeys []string `yaml:"filter_metadata_keys" env:"BACKEND_FILTER_METADATA_KEYS"` // Comma-separated list of metadata keys to filter out
	// Credential passthrough: if enabled, use credentials from client requests instead of configured credentials
	// This allows respecting client access rights while still using configured credentials as fallback
	UseClientCredentials bool `yaml:"use_client_credentials" env:"BACKEND_USE_CLIENT_CREDENTIALS"`
}

// EncryptionConfig holds encryption-related configuration.
type EncryptionConfig struct {
	Password            string           `yaml:"password" env:"ENCRYPTION_PASSWORD"`
	KeyFile             string           `yaml:"key_file" env:"ENCRYPTION_KEY_FILE"`
	PreferredAlgorithm  string           `yaml:"preferred_algorithm" env:"ENCRYPTION_PREFERRED_ALGORITHM"`
	SupportedAlgorithms []string         `yaml:"supported_algorithms" env:"ENCRYPTION_SUPPORTED_ALGORITHMS"`
	KeyManager          KeyManagerConfig `yaml:"key_manager"`
	ChunkedMode         bool             `yaml:"chunked_mode" env:"ENCRYPTION_CHUNKED_MODE"` // Enable chunked/streaming encryption
	ChunkSize           int              `yaml:"chunk_size" env:"ENCRYPTION_CHUNK_SIZE"`     // Size of each encryption chunk in bytes
	Hardware            HardwareConfig   `yaml:"hardware"`
}

// HardwareConfig holds hardware acceleration configuration.
type HardwareConfig struct {
	// EnableAESNI enables AES-NI hardware acceleration on x86_64 architectures.
	// Default: true
	EnableAESNI bool `yaml:"enable_aesni" env:"HARDWARE_ENABLE_AESNI"`

	// EnableARMv8AES enables ARMv8 AES hardware acceleration on ARM64 architectures.
	// Default: true
	EnableARMv8AES bool `yaml:"enable_armv8_aes" env:"HARDWARE_ENABLE_ARMV8_AES"`
}

// KeyManagerConfig holds key manager (KMS) configuration.
//
// Currently supported providers:
//   - "cosmian" or "kmip": Cosmian KMIP (fully implemented in v0.5)
//   - "memory": In-process AES key-wrap — suitable for single-node deployments,
//     tests, and local development without an external KMS (v0.6)
//   - "hsm": PKCS#11 Hardware Security Module (skeleton in v0.6; functional in v1.0;
//     requires -tags hsm build flag — see docs/adr/0004-hsm-adapter-contract.md)
//
// Planned providers (v1.0):
//   - "aws" or "aws-kms": AWS KMS (see V1.0-KMS-2)
//   - "vault" or "vault-transit": HashiCorp Vault Transit (see V1.0-KMS-3)
//
// See docs/KMS_COMPATIBILITY.md for implementation status and adapter options.
type KeyManagerConfig struct {
	Enabled        bool                 `yaml:"enabled" env:"KEY_MANAGER_ENABLED"`
	Provider       string               `yaml:"provider" env:"KEY_MANAGER_PROVIDER"`
	DualReadWindow int                  `yaml:"dual_read_window" env:"KEY_MANAGER_DUAL_READ_WINDOW"`
	RotationPolicy RotationPolicyConfig `yaml:"rotation_policy"`
	Cosmian        CosmianConfig        `yaml:"cosmian"`
	Memory         MemoryKMConfig       `yaml:"memory"`
	// TODO(v1.0): Add AWS and Vault config fields when adapters are implemented
	// AWS        AWSKMSConfig  `yaml:"aws"`
	// Vault      VaultConfig   `yaml:"vault"`
}

// MemoryKMConfig captures settings for the in-memory key manager adapter.
//
// The master key is loaded from the configured source once at startup and is
// never written to disk by the gateway. Supported secret reference formats for
// MasterKeySource:
//
//   - "env:VAR"   — read from environment variable VAR
//   - "file:PATH" — read from file at PATH (hex-encoded or raw bytes)
//   - ""          — auto-generate a random key (suitable for tests only;
//     keys are NOT persisted and all wrapped DEKs are lost on restart)
type MemoryKMConfig struct {
	// MasterKeySource is a secret reference or empty string (auto-generate).
	MasterKeySource string `yaml:"master_key_source" env:"MEMORY_KM_MASTER_KEY_SOURCE"`
}

// RotationPolicyConfig holds key rotation policy configuration.
type RotationPolicyConfig struct {
	// Enabled enables automatic rotation policy tracking and audit events.
	// Note: Actual rotation must be performed manually by updating the key configuration.
	Enabled bool `yaml:"enabled" env:"KEY_MANAGER_ROTATION_POLICY_ENABLED"`
	// GraceWindow is the duration after rotation during which both old and new keys are accepted.
	// This should match or exceed DualReadWindow in practice.
	// Default: 0 (disabled, use DualReadWindow instead)
	GraceWindow time.Duration `yaml:"grace_window" env:"KEY_MANAGER_ROTATION_GRACE_WINDOW"`
}

// CosmianConfig captures settings for the Cosmian KMIP integration.
type CosmianConfig struct {
	Endpoint           string                `yaml:"endpoint" env:"COSMIAN_KMS_ENDPOINT"`
	Timeout            time.Duration         `yaml:"timeout" env:"COSMIAN_KMS_TIMEOUT"`
	Keys               []CosmianKeyReference `yaml:"keys"`
	ClientCert         string                `yaml:"client_cert" env:"COSMIAN_KMS_CLIENT_CERT"`
	ClientKey          string                `yaml:"client_key" env:"COSMIAN_KMS_CLIENT_KEY"`
	CACert             string                `yaml:"ca_cert" env:"COSMIAN_KMS_CA_CERT"`
	InsecureSkipVerify bool                  `yaml:"insecure_skip_verify" env:"COSMIAN_KMS_INSECURE_SKIP_VERIFY"`
}

// CosmianKeyReference maps wrapping key identifiers to metadata versions.
type CosmianKeyReference struct {
	ID      string `yaml:"id"`
	Version int    `yaml:"version"`
}

// CompressionConfig holds compression settings.
type CompressionConfig struct {
	Enabled      bool     `yaml:"enabled" env:"COMPRESSION_ENABLED"`
	MinSize      int64    `yaml:"min_size" env:"COMPRESSION_MIN_SIZE"`
	ContentTypes []string `yaml:"content_types" env:"COMPRESSION_CONTENT_TYPES"`
	Algorithm    string   `yaml:"algorithm" env:"COMPRESSION_ALGORITHM"`
	Level        int      `yaml:"level" env:"COMPRESSION_LEVEL"`
}

// TLSConfig holds TLS configuration.
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled" env:"TLS_ENABLED"`
	CertFile string `yaml:"cert_file" env:"TLS_CERT_FILE"`
	KeyFile  string `yaml:"key_file" env:"TLS_KEY_FILE"`
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	ReadTimeout       time.Duration `yaml:"read_timeout" env:"SERVER_READ_TIMEOUT"`
	WriteTimeout      time.Duration `yaml:"write_timeout" env:"SERVER_WRITE_TIMEOUT"`
	IdleTimeout       time.Duration `yaml:"idle_timeout" env:"SERVER_IDLE_TIMEOUT"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout" env:"SERVER_READ_HEADER_TIMEOUT"`
	MaxHeaderBytes    int           `yaml:"max_header_bytes" env:"SERVER_MAX_HEADER_BYTES"`
	// DisableMultipartUploads disables multipart upload operations to ensure all data is encrypted
	DisableMultipartUploads bool `yaml:"disable_multipart_uploads" env:"SERVER_DISABLE_MULTIPART_UPLOADS"`
	// MaxLegacyCopySourceBytes caps the object size the legacy (non-chunked)
	// UploadPartCopy fallback path is willing to buffer in memory. Legacy
	// single-AEAD objects cannot be range-decrypted, so copying from one
	// requires reading the entire source into memory. The default is a
	// conservative 256 MiB (opt-out safety posture): operators who need a
	// higher limit MUST explicitly raise this and size pod memory for
	// max_concurrent_copies × cap. Exceeded requests return 400
	// InvalidRequest with a message pointing operators at the chunked
	// encryption migration path. A value ≤ 0 is treated as the default.
	MaxLegacyCopySourceBytes int64 `yaml:"max_legacy_copy_source_bytes" env:"SERVER_MAX_LEGACY_COPY_SOURCE_BYTES"`
}

// DefaultMaxLegacyCopySourceBytes is the default cap for the legacy
// UploadPartCopy fallback path (256 MiB). See ServerConfig.MaxLegacyCopySourceBytes.
const DefaultMaxLegacyCopySourceBytes int64 = 256 * 1024 * 1024

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	Enabled bool          `yaml:"enabled" env:"RATE_LIMIT_ENABLED"`
	Limit   int           `yaml:"limit" env:"RATE_LIMIT_REQUESTS"`
	Window  time.Duration `yaml:"window" env:"RATE_LIMIT_WINDOW"`
}

// CacheConfig holds cache configuration.
type CacheConfig struct {
	Enabled    bool          `yaml:"enabled" env:"CACHE_ENABLED"`
	MaxSize    int64         `yaml:"max_size" env:"CACHE_MAX_SIZE"`       // Max size in bytes
	MaxItems   int           `yaml:"max_items" env:"CACHE_MAX_ITEMS"`     // Max number of items
	DefaultTTL time.Duration `yaml:"default_ttl" env:"CACHE_DEFAULT_TTL"` // Default TTL
}

// AuditConfig holds audit logging configuration.
type AuditConfig struct {
	Enabled            bool       `yaml:"enabled" env:"AUDIT_ENABLED"`
	MaxEvents          int        `yaml:"max_events" env:"AUDIT_MAX_EVENTS"` // Max events to keep in memory
	Sink               SinkConfig `yaml:"sink"`
	RedactMetadataKeys []string   `yaml:"redact_metadata_keys" env:"AUDIT_REDACT_METADATA_KEYS"`
}

// SinkConfig holds audit sink configuration.
type SinkConfig struct {
	Type          string            `yaml:"type" env:"AUDIT_SINK_TYPE"` // stdout, file, http
	Endpoint      string            `yaml:"endpoint" env:"AUDIT_SINK_ENDPOINT"`
	FilePath      string            `yaml:"file_path" env:"AUDIT_SINK_FILE_PATH"`
	Headers       map[string]string `yaml:"headers"` // Custom headers for HTTP sink
	BatchSize     int               `yaml:"batch_size" env:"AUDIT_SINK_BATCH_SIZE"`
	FlushInterval time.Duration     `yaml:"flush_interval" env:"AUDIT_SINK_FLUSH_INTERVAL"`
	RetryCount    int               `yaml:"retry_count" env:"AUDIT_SINK_RETRY_COUNT"`
	RetryBackoff  time.Duration     `yaml:"retry_backoff" env:"AUDIT_SINK_RETRY_BACKOFF"`
}

// TracingConfig holds OpenTelemetry tracing configuration.
type TracingConfig struct {
	Enabled         bool    `yaml:"enabled" env:"TRACING_ENABLED"`                   // Enable/disable tracing
	ServiceName     string  `yaml:"service_name" env:"TRACING_SERVICE_NAME"`         // Service name for traces
	ServiceVersion  string  `yaml:"service_version" env:"TRACING_SERVICE_VERSION"`   // Service version
	Exporter        string  `yaml:"exporter" env:"TRACING_EXPORTER"`                 // Exporter type: stdout, jaeger, otlp
	JaegerEndpoint  string  `yaml:"jaeger_endpoint" env:"TRACING_JAEGER_ENDPOINT"`   // Jaeger collector endpoint
	OtlpEndpoint    string  `yaml:"otlp_endpoint" env:"TRACING_OTLP_ENDPOINT"`       // OTLP gRPC endpoint
	SamplingRatio   float64 `yaml:"sampling_ratio" env:"TRACING_SAMPLING_RATIO"`     // Sampling ratio (0.0-1.0)
	RedactSensitive bool    `yaml:"redact_sensitive" env:"TRACING_REDACT_SENSITIVE"` // Redact sensitive data in spans
}

// MetricsConfig holds metrics configuration.
type MetricsConfig struct {
	EnableBucketLabel bool `yaml:"enable_bucket_label" env:"METRICS_ENABLE_BUCKET_LABEL"`
}

// LoggingConfig holds access logging configuration.
type LoggingConfig struct {
	AccessLogFormat string   `yaml:"access_log_format" env:"LOGGING_ACCESS_LOG_FORMAT"` // Access log format: default, json, clf
	RedactHeaders   []string `yaml:"redact_headers" env:"LOGGING_REDACT_HEADERS"`       // Headers to redact in access logs (comma-separated)
}

// AdminConfig holds admin API configuration.
//
// The admin endpoint runs on a separate listener from the S3 data-plane,
// gated by bearer-token authentication with constant-time comparison.
// When enabled on a non-loopback address, TLS must be enabled.
type AdminConfig struct {
	Enabled   bool           `yaml:"enabled" env:"ADMIN_ENABLED"`
	Address   string         `yaml:"address" env:"ADMIN_ADDRESS"`
	TLS       AdminTLSConfig `yaml:"tls"`
	Auth      AdminAuthConfig `yaml:"auth"`
	RateLimit AdminRateLimitConfig `yaml:"rate_limit"`
}

// AdminTLSConfig holds TLS settings for the admin listener.
type AdminTLSConfig struct {
	Enabled  bool   `yaml:"enabled" env:"ADMIN_TLS_ENABLED"`
	CertFile string `yaml:"cert_file" env:"ADMIN_TLS_CERT_FILE"`
	KeyFile  string `yaml:"key_file" env:"ADMIN_TLS_KEY_FILE"`
}

// AdminAuthConfig holds authentication settings for the admin API.
type AdminAuthConfig struct {
	Type      string `yaml:"type" env:"ADMIN_AUTH_TYPE"`           // Only "bearer" in v0.6
	TokenFile string `yaml:"token_file" env:"ADMIN_AUTH_TOKEN_FILE"` // File path; 0600, never inline
	Token     string `yaml:"token" env:"ADMIN_AUTH_TOKEN"`          // Inline only with ADMIN_ALLOW_INLINE_TOKEN=1
}

// AdminRateLimitConfig holds rate-limiting settings for the admin API.
type AdminRateLimitConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute" env:"ADMIN_RATE_LIMIT_RPM"`
}

// MultipartStateConfig holds configuration for the multipart-upload encryption state store.
type MultipartStateConfig struct {
	Valkey ValkeyConfig `yaml:"valkey"`
}

// ValkeyConfig holds the connection settings for the Valkey state store.
type ValkeyConfig struct {
	Addr   string `yaml:"addr" env:"VALKEY_ADDR"`   // e.g. "valkey.internal:6379"
	// Username for Valkey 6.0+ ACL auth (optional).
	Username string `yaml:"username" env:"VALKEY_USERNAME"`
	// PasswordEnv is the name of the environment variable that holds the
	// plaintext password. Never the literal password.
	PasswordEnv string `yaml:"password_env" env:"VALKEY_PASSWORD_ENV"`
	DB          int    `yaml:"db" env:"VALKEY_DB"`
	TLS         ValkeyTLSConfig `yaml:"tls"`
	// InsecureAllowPlaintext permits a non-TLS Valkey connection.
	// Development only. A startup warning and metric are emitted when true.
	InsecureAllowPlaintext bool          `yaml:"insecure_allow_plaintext" env:"VALKEY_INSECURE_ALLOW_PLAINTEXT"`
	TTLSeconds             int           `yaml:"ttl_seconds" env:"VALKEY_TTL_SECONDS"`
	DialTimeout            time.Duration `yaml:"dial_timeout" env:"VALKEY_DIAL_TIMEOUT"`
	ReadTimeout            time.Duration `yaml:"read_timeout" env:"VALKEY_READ_TIMEOUT"`
	WriteTimeout           time.Duration `yaml:"write_timeout" env:"VALKEY_WRITE_TIMEOUT"`
	PoolSize               int           `yaml:"pool_size" env:"VALKEY_POOL_SIZE"`
	MinIdleConns           int           `yaml:"min_idle_conns" env:"VALKEY_MIN_IDLE_CONNS"`
}

// ValkeyTLSConfig holds TLS settings for the Valkey connection.
type ValkeyTLSConfig struct {
	Enabled            bool   `yaml:"enabled" env:"VALKEY_TLS_ENABLED"`
	CAFile             string `yaml:"ca_file" env:"VALKEY_TLS_CA_FILE"`
	CertFile           string `yaml:"cert_file" env:"VALKEY_TLS_CERT_FILE"`
	KeyFile            string `yaml:"key_file" env:"VALKEY_TLS_KEY_FILE"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify" env:"VALKEY_TLS_INSECURE_SKIP_VERIFY"`
	// MinVersion is the minimum TLS version: "1.2" or "1.3" (default "1.3").
	MinVersion string `yaml:"min_version" env:"VALKEY_TLS_MIN_VERSION"`
}

const (
	// ValkeyDefaultTTLSeconds is the default state TTL (7 days).
	ValkeyDefaultTTLSeconds = 7 * 24 * 60 * 60
)

// LoadConfig loads configuration from a file and environment variables.
func LoadConfig(path string) (*Config, error) {
	config := &Config{
		ListenAddr: ":8080",
		LogLevel:   "info",
		Encryption: EncryptionConfig{
			KeyManager: KeyManagerConfig{
				Provider:       "cosmian",
				DualReadWindow: 1,
				RotationPolicy: RotationPolicyConfig{
					Enabled:     false,
					GraceWindow: 0, // Use DualReadWindow by default
				},
			},
			Hardware: HardwareConfig{
				EnableAESNI:    true,
				EnableARMv8AES: true,
			},
		},
		Backend: BackendConfig{
			Endpoint: "", // Leave empty for AWS default, or set for any S3-compatible endpoint
			Region:   "us-east-1",
			UseSSL:   true,
		},
		Compression: CompressionConfig{
			Enabled:   false,
			MinSize:   1024,
			Algorithm: "gzip",
			Level:     6,
		},
		Server: ServerConfig{
			ReadTimeout:              15 * time.Second,
			WriteTimeout:             15 * time.Second,
			IdleTimeout:              60 * time.Second,
			ReadHeaderTimeout:        10 * time.Second,
			MaxHeaderBytes:           1 << 20, // 1MB
			DisableMultipartUploads:  false,   // Allow multipart uploads by default for compatibility
			MaxLegacyCopySourceBytes: DefaultMaxLegacyCopySourceBytes,
		},
		RateLimit: RateLimitConfig{
			Enabled: false,
			Limit:   100,
			Window:  60 * time.Second,
		},
		Cache: CacheConfig{
			Enabled:    false,
			MaxSize:    100 * 1024 * 1024, // 100MB default
			MaxItems:   1000,
			DefaultTTL: 5 * time.Minute,
		},
		Audit: AuditConfig{
			Enabled:   false,
			MaxEvents: 10000,
		},
		Tracing: TracingConfig{
			Enabled:         false,
			ServiceName:     "s3-encryption-gateway",
			ServiceVersion:  "dev",
			Exporter:        "stdout",
			SamplingRatio:   1.0,
			RedactSensitive: true,
		},
		Metrics: MetricsConfig{
			EnableBucketLabel: true,
		},
		Logging: LoggingConfig{
			AccessLogFormat: "default",
			RedactHeaders:   []string{"authorization", "x-amz-security-token", "x-amz-signature", "x-encryption-key", "x-encryption-password"},
		},
		Admin: AdminConfig{
			Enabled: false,
			Address: "127.0.0.1:8081",
			Auth: AdminAuthConfig{
				Type: "bearer",
			},
			RateLimit: AdminRateLimitConfig{
				RequestsPerMinute: 30,
			},
		},
		MultipartState: MultipartStateConfig{
			Valkey: ValkeyConfig{
				TTLSeconds:   ValkeyDefaultTTLSeconds,
				DialTimeout:  2 * time.Second,
				ReadTimeout:  1 * time.Second,
				WriteTimeout: 1 * time.Second,
				PoolSize:     16,
				MinIdleConns: 2,
				TLS: ValkeyTLSConfig{
					Enabled:    true,
					MinVersion: "1.3",
				},
			},
		},
	}

	// Load from file if provided
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		if len(data) > 0 {
			if err := yaml.Unmarshal(data, config); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		}
	}

	// Override with environment variables
	loadFromEnv(config)

	// Set default hardware acceleration flags if not specified (default true)
	// This logic is now handled by initialization values above, but we check env vars here
	// if they were set to override default initialization.
	// Actually, loadFromEnv handles it.

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// isEnvSet checks if an environment variable is set
func isEnvSet(key string) bool {
	_, ok := os.LookupEnv(key)
	return ok
}

// loadFromEnv loads configuration values from environment variables.
func loadFromEnv(config *Config) {
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		config.ListenAddr = v
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		config.LogLevel = v
	}
	if v := os.Getenv("BACKEND_ENDPOINT"); v != "" {
		config.Backend.Endpoint = v
	}
	if v := os.Getenv("BACKEND_REGION"); v != "" {
		config.Backend.Region = v
	}
	if v := os.Getenv("BACKEND_ACCESS_KEY"); v != "" {
		config.Backend.AccessKey = v
	}
	if v := os.Getenv("BACKEND_SECRET_KEY"); v != "" {
		config.Backend.SecretKey = v
	}
	if v := os.Getenv("BACKEND_PROVIDER"); v != "" {
		config.Backend.Provider = v
	}
	if v := os.Getenv("BACKEND_USE_PATH_STYLE"); v != "" {
		config.Backend.UsePathStyle = v == "true" || v == "1"
	}
	if v := os.Getenv("BACKEND_FILTER_METADATA_KEYS"); v != "" {
		// Comma-separated list of metadata keys to filter out
		config.Backend.FilterMetadataKeys = strings.Split(v, ",")
		for i := range config.Backend.FilterMetadataKeys {
			config.Backend.FilterMetadataKeys[i] = strings.TrimSpace(config.Backend.FilterMetadataKeys[i])
		}
	}
	if v := os.Getenv("BACKEND_USE_CLIENT_CREDENTIALS"); v != "" {
		config.Backend.UseClientCredentials = v == "true" || v == "1"
	}
	if v := os.Getenv("ENCRYPTION_PASSWORD"); v != "" {
		config.Encryption.Password = v
	}
	if v := os.Getenv("ENCRYPTION_KEY_FILE"); v != "" {
		config.Encryption.KeyFile = v
	}
	if v := os.Getenv("ENCRYPTION_PREFERRED_ALGORITHM"); v != "" {
		config.Encryption.PreferredAlgorithm = v
	}
	if v := os.Getenv("ENCRYPTION_SUPPORTED_ALGORITHMS"); v != "" {
		// Comma-separated list of algorithms
		config.Encryption.SupportedAlgorithms = strings.Split(v, ",")
		for i := range config.Encryption.SupportedAlgorithms {
			config.Encryption.SupportedAlgorithms[i] = strings.TrimSpace(config.Encryption.SupportedAlgorithms[i])
		}
	}
	if v := os.Getenv("HARDWARE_ENABLE_AESNI"); v != "" {
		config.Encryption.Hardware.EnableAESNI = v == "true" || v == "1"
	}
	if v := os.Getenv("HARDWARE_ENABLE_ARMV8_AES"); v != "" {
		config.Encryption.Hardware.EnableARMv8AES = v == "true" || v == "1"
	}
	if v := os.Getenv("KEY_MANAGER_ENABLED"); v != "" {
		config.Encryption.KeyManager.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("KEY_MANAGER_PROVIDER"); v != "" {
		config.Encryption.KeyManager.Provider = v
	}
	if v := os.Getenv("KEY_MANAGER_DUAL_READ_WINDOW"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			config.Encryption.KeyManager.DualReadWindow = n
		}
	}
	if v := os.Getenv("KEY_MANAGER_ROTATION_POLICY_ENABLED"); v != "" {
		config.Encryption.KeyManager.RotationPolicy.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("KEY_MANAGER_ROTATION_GRACE_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Encryption.KeyManager.RotationPolicy.GraceWindow = d
		}
	}
	if v := os.Getenv("COSMIAN_KMS_ENDPOINT"); v != "" {
		config.Encryption.KeyManager.Cosmian.Endpoint = v
	}
	if v := os.Getenv("COSMIAN_KMS_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Encryption.KeyManager.Cosmian.Timeout = d
		}
	}
	if v := os.Getenv("COSMIAN_KMS_CLIENT_CERT"); v != "" {
		config.Encryption.KeyManager.Cosmian.ClientCert = v
	}
	if v := os.Getenv("COSMIAN_KMS_CLIENT_KEY"); v != "" {
		config.Encryption.KeyManager.Cosmian.ClientKey = v
	}
	if v := os.Getenv("COSMIAN_KMS_CA_CERT"); v != "" {
		config.Encryption.KeyManager.Cosmian.CACert = v
	}
	if v := os.Getenv("COSMIAN_KMS_INSECURE_SKIP_VERIFY"); v != "" {
		config.Encryption.KeyManager.Cosmian.InsecureSkipVerify = v == "true" || v == "1"
	}
	if v := os.Getenv("COSMIAN_KMS_KEYS"); v != "" {
		config.Encryption.KeyManager.Cosmian.Keys = parseCosmianKeyRefs(v)
	}
	if v := os.Getenv("TLS_ENABLED"); v != "" {
		config.TLS.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("TLS_CERT_FILE"); v != "" {
		config.TLS.CertFile = v
	}
	if v := os.Getenv("TLS_KEY_FILE"); v != "" {
		config.TLS.KeyFile = v
	}
	// Server timeouts from environment
	if v := os.Getenv("SERVER_READ_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Server.ReadTimeout = d
		}
	}
	if v := os.Getenv("SERVER_WRITE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Server.WriteTimeout = d
		}
	}
	if v := os.Getenv("SERVER_IDLE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Server.IdleTimeout = d
		}
	}
	if v := os.Getenv("SERVER_READ_HEADER_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Server.ReadHeaderTimeout = d
		}
	}
	if v := os.Getenv("SERVER_MAX_HEADER_BYTES"); v != "" {
		var maxBytes int
		if _, err := fmt.Sscanf(v, "%d", &maxBytes); err == nil && maxBytes > 0 {
			config.Server.MaxHeaderBytes = maxBytes
		}
	}
	if v := os.Getenv("RATE_LIMIT_ENABLED"); v != "" {
		config.RateLimit.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("RATE_LIMIT_REQUESTS"); v != "" {
		var limit int
		if _, err := fmt.Sscanf(v, "%d", &limit); err == nil && limit > 0 {
			config.RateLimit.Limit = limit
		}
	}
	if v := os.Getenv("RATE_LIMIT_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.RateLimit.Window = d
		}
	}
	// Cache configuration
	if v := os.Getenv("CACHE_ENABLED"); v != "" {
		config.Cache.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("CACHE_MAX_SIZE"); v != "" {
		var maxSize int64
		if _, err := fmt.Sscanf(v, "%d", &maxSize); err == nil && maxSize > 0 {
			config.Cache.MaxSize = maxSize
		}
	}
	if v := os.Getenv("CACHE_MAX_ITEMS"); v != "" {
		var maxItems int
		if _, err := fmt.Sscanf(v, "%d", &maxItems); err == nil && maxItems > 0 {
			config.Cache.MaxItems = maxItems
		}
	}
	if v := os.Getenv("CACHE_DEFAULT_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Cache.DefaultTTL = d
		}
	}
	// Audit configuration
	if v := os.Getenv("AUDIT_ENABLED"); v != "" {
		config.Audit.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("AUDIT_MAX_EVENTS"); v != "" {
		var maxEvents int
		if _, err := fmt.Sscanf(v, "%d", &maxEvents); err == nil && maxEvents > 0 {
			config.Audit.MaxEvents = maxEvents
		}
	}
	// Audit Sink configuration
	if v := os.Getenv("AUDIT_SINK_TYPE"); v != "" {
		config.Audit.Sink.Type = v
	}
	if v := os.Getenv("AUDIT_SINK_ENDPOINT"); v != "" {
		config.Audit.Sink.Endpoint = v
	}
	if v := os.Getenv("AUDIT_SINK_FILE_PATH"); v != "" {
		config.Audit.Sink.FilePath = v
	}
	if v := os.Getenv("AUDIT_SINK_BATCH_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			config.Audit.Sink.BatchSize = n
		}
	}
	if v := os.Getenv("AUDIT_SINK_FLUSH_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Audit.Sink.FlushInterval = d
		}
	}
	if v := os.Getenv("AUDIT_SINK_RETRY_COUNT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			config.Audit.Sink.RetryCount = n
		}
	}
	if v := os.Getenv("AUDIT_SINK_RETRY_BACKOFF"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Audit.Sink.RetryBackoff = d
		}
	}
	if v := os.Getenv("AUDIT_REDACT_METADATA_KEYS"); v != "" {
		config.Audit.RedactMetadataKeys = strings.Split(v, ",")
		for i := range config.Audit.RedactMetadataKeys {
			config.Audit.RedactMetadataKeys[i] = strings.TrimSpace(config.Audit.RedactMetadataKeys[i])
		}
	}
	// Proxied bucket configuration
	if v := os.Getenv("PROXIED_BUCKET"); v != "" {
		config.ProxiedBucket = v
	}
	// Tracing configuration
	if v := os.Getenv("TRACING_ENABLED"); v != "" {
		config.Tracing.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("TRACING_SERVICE_NAME"); v != "" {
		config.Tracing.ServiceName = v
	}
	if v := os.Getenv("TRACING_SERVICE_VERSION"); v != "" {
		config.Tracing.ServiceVersion = v
	}
	if v := os.Getenv("TRACING_EXPORTER"); v != "" {
		config.Tracing.Exporter = v
	}
	if v := os.Getenv("TRACING_JAEGER_ENDPOINT"); v != "" {
		config.Tracing.JaegerEndpoint = v
	}
	if v := os.Getenv("TRACING_OTLP_ENDPOINT"); v != "" {
		config.Tracing.OtlpEndpoint = v
	}
	if v := os.Getenv("TRACING_SAMPLING_RATIO"); v != "" {
		if ratio, err := strconv.ParseFloat(v, 64); err == nil && ratio >= 0.0 && ratio <= 1.0 {
			config.Tracing.SamplingRatio = ratio
		}
	}
	if v := os.Getenv("TRACING_REDACT_SENSITIVE"); v != "" {
		config.Tracing.RedactSensitive = v == "true" || v == "1"
	}
	// Metrics configuration
	if v := os.Getenv("METRICS_ENABLE_BUCKET_LABEL"); v != "" {
		config.Metrics.EnableBucketLabel = v == "true" || v == "1"
	}
	// Logging configuration
	if v := os.Getenv("LOGGING_ACCESS_LOG_FORMAT"); v != "" {
		config.Logging.AccessLogFormat = v
	}
	if v := os.Getenv("LOGGING_REDACT_HEADERS"); v != "" {
		// Comma-separated list of headers to redact
		config.Logging.RedactHeaders = strings.Split(v, ",")
		for i := range config.Logging.RedactHeaders {
			config.Logging.RedactHeaders[i] = strings.TrimSpace(config.Logging.RedactHeaders[i])
		}
	}
	if v := os.Getenv("POLICIES"); v != "" {
		config.PolicyFiles = strings.Split(v, ",")
		for i := range config.PolicyFiles {
			config.PolicyFiles[i] = strings.TrimSpace(config.PolicyFiles[i])
		}
	}
	// Admin configuration
	if v := os.Getenv("ADMIN_ENABLED"); v != "" {
		config.Admin.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("ADMIN_ADDRESS"); v != "" {
		config.Admin.Address = v
	}
	if v := os.Getenv("ADMIN_TLS_ENABLED"); v != "" {
		config.Admin.TLS.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("ADMIN_TLS_CERT_FILE"); v != "" {
		config.Admin.TLS.CertFile = v
	}
	if v := os.Getenv("ADMIN_TLS_KEY_FILE"); v != "" {
		config.Admin.TLS.KeyFile = v
	}
	if v := os.Getenv("ADMIN_AUTH_TYPE"); v != "" {
		config.Admin.Auth.Type = v
	}
	if v := os.Getenv("ADMIN_AUTH_TOKEN_FILE"); v != "" {
		config.Admin.Auth.TokenFile = v
	}
	if v := os.Getenv("ADMIN_AUTH_TOKEN"); v != "" {
		config.Admin.Auth.Token = v
	}
	if v := os.Getenv("ADMIN_RATE_LIMIT_RPM"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			config.Admin.RateLimit.RequestsPerMinute = n
		}
	}
}

func parseCosmianKeyRefs(value string) []CosmianKeyReference {
	parts := strings.Split(value, ",")
	refs := make([]CosmianKeyReference, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ref := CosmianKeyReference{}
		if strings.Contains(part, ":") {
			pieces := strings.SplitN(part, ":", 2)
			ref.ID = strings.TrimSpace(pieces[0])
			if len(pieces) == 2 {
				if n, err := strconv.Atoi(strings.TrimSpace(pieces[1])); err == nil {
					ref.Version = n
				}
			}
		} else {
			ref.ID = part
		}
		refs = append(refs, ref)
	}
	return refs
}

// Validate validates the configuration and returns an error if invalid.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}

	// Endpoint is optional - if empty, AWS SDK will use default AWS endpoints

	// Backend credentials: required unless use_client_credentials is enabled
	// When use_client_credentials is enabled, credentials must come from client requests
	if !c.Backend.UseClientCredentials {
		if c.Backend.AccessKey == "" {
			return fmt.Errorf("backend.access_key is required (or enable backend.use_client_credentials)")
		}

		if c.Backend.SecretKey == "" {
			return fmt.Errorf("backend.secret_key is required (or enable backend.use_client_credentials)")
		}
	}

	if c.Encryption.Password == "" && c.Encryption.KeyFile == "" {
		return fmt.Errorf("either encryption.password or encryption.key_file is required")
	}

	if c.LogLevel != "" {
		validLevels := map[string]bool{
			"debug": true,
			"info":  true,
			"warn":  true,
			"error": true,
		}
		if !validLevels[c.LogLevel] {
			return fmt.Errorf("invalid log_level: %s (must be debug, info, warn, or error)", c.LogLevel)
		}
	}

	// Validate TLS configuration
	if c.TLS.Enabled {
		if c.TLS.CertFile == "" {
			return fmt.Errorf("tls.cert_file is required when TLS is enabled")
		}
		if c.TLS.KeyFile == "" {
			return fmt.Errorf("tls.key_file is required when TLS is enabled")
		}
	}

	// Validate encryption algorithms policy
	allowed := map[string]bool{
		"AES256-GCM":        true,
		"ChaCha20-Poly1305": true,
	}
	if alg := strings.TrimSpace(c.Encryption.PreferredAlgorithm); alg != "" {
		if !allowed[alg] {
			return fmt.Errorf("invalid encryption.preferred_algorithm: %s", alg)
		}
	}
	if len(c.Encryption.SupportedAlgorithms) > 0 {
		for _, alg := range c.Encryption.SupportedAlgorithms {
			if !allowed[strings.TrimSpace(alg)] {
				return fmt.Errorf("invalid entry in encryption.supported_algorithms: %s", alg)
			}
		}
	}

	if c.Encryption.KeyManager.Enabled {
		if c.Encryption.KeyManager.Provider == "" {
			return fmt.Errorf("encryption.key_manager.provider is required when key manager is enabled")
		}
		switch strings.ToLower(c.Encryption.KeyManager.Provider) {
		case "cosmian", "kmip":
			if c.Encryption.KeyManager.Cosmian.Endpoint == "" {
				return fmt.Errorf("encryption.key_manager.cosmian.endpoint is required")
			}
			if len(c.Encryption.KeyManager.Cosmian.Keys) == 0 {
				return fmt.Errorf("encryption.key_manager.cosmian.keys must include at least one entry")
			}
		case "memory":
			// No mandatory fields; master_key_source is optional (auto-generate if empty)
		case "hsm":
			// Validated at runtime by the HSM adapter; build-tag check not possible here
		default:
			return fmt.Errorf("unsupported key manager provider: %s (supported: cosmian, kmip, memory, hsm)", c.Encryption.KeyManager.Provider)
		}
	}

	// Validate tracing configuration
	if c.Tracing.Enabled {
		if c.Tracing.ServiceName == "" {
			return fmt.Errorf("tracing.service_name is required when tracing is enabled")
		}
		validExporters := map[string]bool{
			"stdout": true,
			"jaeger": true,
			"otlp":   true,
		}
		if !validExporters[c.Tracing.Exporter] {
			return fmt.Errorf("invalid tracing.exporter: %s (must be stdout, jaeger, or otlp)", c.Tracing.Exporter)
		}
		if c.Tracing.SamplingRatio < 0.0 || c.Tracing.SamplingRatio > 1.0 {
			return fmt.Errorf("tracing.sampling_ratio must be between 0.0 and 1.0")
		}
		if c.Tracing.Exporter == "jaeger" && c.Tracing.JaegerEndpoint == "" {
			return fmt.Errorf("tracing.jaeger_endpoint is required when exporter is jaeger")
		}
		if c.Tracing.Exporter == "otlp" && c.Tracing.OtlpEndpoint == "" {
			return fmt.Errorf("tracing.otlp_endpoint is required when exporter is otlp")
		}
	}

	// Validate logging configuration
	if c.Logging.AccessLogFormat != "" {
		validFormats := map[string]bool{
			"default": true,
			"json":    true,
			"clf":     true,
		}
		if !validFormats[c.Logging.AccessLogFormat] {
			return fmt.Errorf("invalid logging.access_log_format: %s (must be default, json, or clf)", c.Logging.AccessLogFormat)
		}
	}

	// Validate audit configuration
	if c.Audit.Enabled {
		switch c.Audit.Sink.Type {
		case "", "stdout":
			// Valid, no extra config needed
		case "file":
			if c.Audit.Sink.FilePath == "" {
				return fmt.Errorf("audit.sink.file_path is required when sink type is file")
			}
		case "http":
			if c.Audit.Sink.Endpoint == "" {
				return fmt.Errorf("audit.sink.endpoint is required when sink type is http")
			}
		default:
			return fmt.Errorf("invalid audit.sink.type: %s (must be stdout, file, or http)", c.Audit.Sink.Type)
		}
	}

	// Validate admin configuration
	if c.Admin.Enabled {
		if c.Admin.Address == "" {
			return fmt.Errorf("admin.address is required when admin is enabled")
		}

		// Ensure admin address differs from data-plane address
		if c.Admin.Address == c.ListenAddr {
			return fmt.Errorf("admin.address must differ from listen_addr")
		}

		// Non-loopback address requires TLS
		if !isLoopbackAddress(c.Admin.Address) && !c.Admin.TLS.Enabled {
			return fmt.Errorf("admin.tls.enabled must be true when admin.address is not loopback (got %s)", c.Admin.Address)
		}

		// TLS cert/key validation
		if c.Admin.TLS.Enabled {
			if c.Admin.TLS.CertFile == "" {
				return fmt.Errorf("admin.tls.cert_file is required when admin TLS is enabled")
			}
			if c.Admin.TLS.KeyFile == "" {
				return fmt.Errorf("admin.tls.key_file is required when admin TLS is enabled")
			}
		}

		// Auth type must be "bearer"
		if c.Admin.Auth.Type != "" && c.Admin.Auth.Type != "bearer" {
			return fmt.Errorf("admin.auth.type must be \"bearer\" (got %q)", c.Admin.Auth.Type)
		}

		// Exactly one of token_file / token must be set
		hasTokenFile := c.Admin.Auth.TokenFile != ""
		hasInlineToken := c.Admin.Auth.Token != ""
		if !hasTokenFile && !hasInlineToken {
			return fmt.Errorf("one of admin.auth.token_file or admin.auth.token is required when admin is enabled")
		}
		if hasTokenFile && hasInlineToken {
			return fmt.Errorf("only one of admin.auth.token_file or admin.auth.token may be set, not both")
		}

		// Inline token requires ADMIN_ALLOW_INLINE_TOKEN=1
		if hasInlineToken && os.Getenv("ADMIN_ALLOW_INLINE_TOKEN") != "1" {
			return fmt.Errorf("admin.auth.token (inline) requires ADMIN_ALLOW_INLINE_TOKEN=1 environment variable")
		}

		// Validate token minimum length (32 bytes decoded)
		if hasTokenFile {
			// Check file permissions
			info, err := os.Stat(c.Admin.Auth.TokenFile)
			if err != nil {
				return fmt.Errorf("admin.auth.token_file: %w", err)
			}
			mode := info.Mode().Perm()
			if mode&0077 != 0 {
				return fmt.Errorf("admin.auth.token_file %s is too permissive (mode %04o); must be 0600 or stricter", c.Admin.Auth.TokenFile, mode)
			}
			// Read and validate token length
			tokenBytes, err := os.ReadFile(c.Admin.Auth.TokenFile)
			if err != nil {
				return fmt.Errorf("admin.auth.token_file: failed to read: %w", err)
			}
			if err := validateAdminTokenLength(strings.TrimSpace(string(tokenBytes))); err != nil {
				return fmt.Errorf("admin.auth.token_file: %w", err)
			}
		}
		if hasInlineToken {
			if err := validateAdminTokenLength(c.Admin.Auth.Token); err != nil {
				return fmt.Errorf("admin.auth.token: %w", err)
			}
		}

		// Validate rate limit
		if c.Admin.RateLimit.RequestsPerMinute <= 0 {
			return fmt.Errorf("admin.rate_limit.requests_per_minute must be positive")
		}
	}

	return nil
}

// isLoopbackAddress checks if the given address string refers to a loopback interface.
func isLoopbackAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validateAdminTokenLength validates that the token is at least 32 bytes when
// decoded from hex or base64, or 32 characters if it is a raw string.
func validateAdminTokenLength(token string) error {
	if token == "" {
		return fmt.Errorf("token is empty")
	}
	// Try hex decode
	if decoded, err := hex.DecodeString(token); err == nil {
		if len(decoded) < 32 {
			return fmt.Errorf("token too short: decoded hex is %d bytes, minimum 32", len(decoded))
		}
		return nil
	}
	// Try base64 decode
	if decoded, err := base64.StdEncoding.DecodeString(token); err == nil {
		if len(decoded) < 32 {
			return fmt.Errorf("token too short: decoded base64 is %d bytes, minimum 32", len(decoded))
		}
		return nil
	}
	// Raw string: require at least 32 characters
	if len(token) < 32 {
		return fmt.Errorf("token too short: %d characters, minimum 32", len(token))
	}
	return nil
}

// ConfigReloader handles hot-reloading of non-crypto configuration settings.
type ConfigReloader struct {
	currentConfig *Config
	configPath    string
	logger        *logrus.Logger
	watcher       *fsnotify.Watcher
	signalChan    chan os.Signal
	stopChan      chan struct{}
	mu            sync.RWMutex
	onReload      func(*Config, *Config) error // callback for applying config changes
}

// NewConfigReloader creates a new configuration reloader that watches for file changes
// and SIGHUP signals to reload non-crypto configuration settings.
func NewConfigReloader(configPath string, initialConfig *Config, logger *logrus.Logger) (*ConfigReloader, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	if configPath != "" {
		if err := watcher.Add(configPath); err != nil {
			watcher.Close()
			return nil, fmt.Errorf("failed to watch config file: %w", err)
		}
	}

	reloader := &ConfigReloader{
		currentConfig: initialConfig,
		configPath:    configPath,
		logger:        logger,
		watcher:       watcher,
		signalChan:    make(chan os.Signal, 1),
		stopChan:      make(chan struct{}),
	}

	// Register for SIGHUP signal
	signal.Notify(reloader.signalChan, syscall.SIGHUP)

	return reloader, nil
}

// SetOnReloadCallback sets the callback function that will be called when configuration
// is reloaded. The callback receives the old and new configs.
func (r *ConfigReloader) SetOnReloadCallback(callback func(old, new *Config) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onReload = callback
}

// Start begins watching for configuration changes. This method blocks until Stop() is called.
func (r *ConfigReloader) Start() {
	r.logger.Info("Configuration hot-reload enabled")

	for {
		select {
		case <-r.stopChan:
			r.logger.Info("Configuration reloader stopping")
			return

		case event, ok := <-r.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) && event.Name == r.configPath {
				r.logger.Info("Configuration file changed, reloading...")
				r.reloadConfig()

			} else if event.Has(fsnotify.Remove) && event.Name == r.configPath {
				r.logger.Warn("Configuration file removed, stopping file watch")
				r.watcher.Remove(r.configPath)
			}

		case err, ok := <-r.watcher.Errors:
			if !ok {
				return
			}
			r.logger.WithError(err).Error("Configuration file watch error")

		case sig := <-r.signalChan:
			if sig == syscall.SIGHUP {
				r.logger.Info("Received SIGHUP, reloading configuration...")
				r.reloadConfig()
			}
		}
	}
}

// Stop stops the configuration reloader.
func (r *ConfigReloader) Stop() {
	close(r.stopChan)
	r.watcher.Close()
	signal.Stop(r.signalChan)
}

// reloadConfig attempts to reload the configuration from disk.
func (r *ConfigReloader) reloadConfig() {
	newConfig, err := LoadConfig(r.configPath)
	if err != nil {
		r.logger.WithError(err).Error("Failed to reload configuration")
		return
	}

	r.mu.RLock()
	oldConfig := *r.currentConfig // Make a copy of the old config
	r.mu.RUnlock()

	// Validate that only safe fields have changed
	if err := r.validateReloadSafety(&oldConfig, newConfig); err != nil {
		r.logger.WithError(err).Error("Configuration reload rejected: unsafe changes detected")
		return
	}

	// Apply the changes via callback
	if r.onReload != nil {
		if err := r.onReload(&oldConfig, newConfig); err != nil {
			r.logger.WithError(err).Error("Failed to apply configuration changes")
			return
		}
	}

	// Update current config
	r.mu.Lock()
	r.currentConfig = newConfig
	r.mu.Unlock()

	r.logger.Info("Configuration reloaded successfully")
}

// validateReloadSafety ensures that only non-crypto settings have changed.
func (r *ConfigReloader) validateReloadSafety(old, new *Config) error {
	// Crypto settings that MUST NOT change during hot reload
	if old.Encryption.Password != new.Encryption.Password {
		return fmt.Errorf("encryption.password cannot be changed during hot reload")
	}
	if old.Encryption.KeyFile != new.Encryption.KeyFile {
		return fmt.Errorf("encryption.key_file cannot be changed during hot reload")
	}
	if old.Encryption.KeyManager.Enabled != new.Encryption.KeyManager.Enabled {
		return fmt.Errorf("encryption.key_manager.enabled cannot be changed during hot reload")
	}
	if old.Encryption.PreferredAlgorithm != new.Encryption.PreferredAlgorithm {
		return fmt.Errorf("encryption.preferred_algorithm cannot be changed during hot reload")
	}
	if len(old.Encryption.SupportedAlgorithms) != len(new.Encryption.SupportedAlgorithms) {
		return fmt.Errorf("encryption.supported_algorithms cannot be changed during hot reload")
	}
	for i, alg := range old.Encryption.SupportedAlgorithms {
		if i >= len(new.Encryption.SupportedAlgorithms) || alg != new.Encryption.SupportedAlgorithms[i] {
			return fmt.Errorf("encryption.supported_algorithms cannot be changed during hot reload")
		}
	}
	if old.Encryption.ChunkedMode != new.Encryption.ChunkedMode {
		return fmt.Errorf("encryption.chunked_mode cannot be changed during hot reload")
	}
	if old.Encryption.ChunkSize != new.Encryption.ChunkSize {
		return fmt.Errorf("encryption.chunk_size cannot be changed during hot reload")
	}
	if old.Encryption.Hardware.EnableAESNI != new.Encryption.Hardware.EnableAESNI {
		return fmt.Errorf("encryption.hardware.enable_aesni cannot be changed during hot reload")
	}
	if old.Encryption.Hardware.EnableARMv8AES != new.Encryption.Hardware.EnableARMv8AES {
		return fmt.Errorf("encryption.hardware.enable_armv8_aes cannot be changed during hot reload")
	}

	// Compression settings - changing these could affect existing encrypted data
	if old.Compression.Enabled != new.Compression.Enabled {
		return fmt.Errorf("compression.enabled cannot be changed during hot reload")
	}
	if old.Compression.Algorithm != new.Compression.Algorithm {
		return fmt.Errorf("compression.algorithm cannot be changed during hot reload")
	}
	if old.Compression.Level != new.Compression.Level {
		return fmt.Errorf("compression.level cannot be changed during hot reload")
	}

	// Backend settings that affect encryption/decryption compatibility
	if old.Backend.Provider != new.Backend.Provider {
		return fmt.Errorf("backend.provider cannot be changed during hot reload")
	}

	// Admin settings — listener is only started/stopped at process start
	if old.Admin.Enabled != new.Admin.Enabled {
		return fmt.Errorf("admin.enabled cannot be changed during hot reload")
	}
	if old.Admin.Address != new.Admin.Address {
		return fmt.Errorf("admin.address cannot be changed during hot reload")
	}
	if old.Admin.TLS.Enabled != new.Admin.TLS.Enabled {
		return fmt.Errorf("admin.tls.enabled cannot be changed during hot reload")
	}
	if old.Admin.TLS.CertFile != new.Admin.TLS.CertFile {
		return fmt.Errorf("admin.tls.cert_file cannot be changed during hot reload")
	}
	if old.Admin.TLS.KeyFile != new.Admin.TLS.KeyFile {
		return fmt.Errorf("admin.tls.key_file cannot be changed during hot reload")
	}

	return nil
}

// GetCurrentConfig returns a copy of the current configuration.
func (r *ConfigReloader) GetCurrentConfig() *Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// Return a copy to prevent external modification
	configCopy := *r.currentConfig
	return &configCopy
}
