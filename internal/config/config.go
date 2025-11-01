package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the complete application configuration.
type Config struct {
	ListenAddr  string            `yaml:"listen_addr" env:"LISTEN_ADDR"`
	LogLevel    string            `yaml:"log_level" env:"LOG_LEVEL"`
	Backend     BackendConfig     `yaml:"backend"`
	Encryption  EncryptionConfig  `yaml:"encryption"`
	Compression CompressionConfig `yaml:"compression"`
	TLS         TLSConfig         `yaml:"tls"`
	Server      ServerConfig      `yaml:"server"`
	RateLimit   RateLimitConfig   `yaml:"rate_limit"`
}

// BackendConfig holds S3 backend configuration.
type BackendConfig struct {
	Endpoint  string `yaml:"endpoint" env:"BACKEND_ENDPOINT"`
	Region    string `yaml:"region" env:"BACKEND_REGION"`
	AccessKey string `yaml:"access_key" env:"BACKEND_ACCESS_KEY"`
	SecretKey string `yaml:"secret_key" env:"BACKEND_SECRET_KEY"`
	Provider  string `yaml:"provider" env:"BACKEND_PROVIDER"` // aws, wasabi, hetzner, minio, digitalocean, backblaze, cloudflare, linode, scaleway, oracle, idrive
	UseSSL    bool   `yaml:"use_ssl" env:"BACKEND_USE_SSL"`
}

// EncryptionConfig holds encryption-related configuration.
type EncryptionConfig struct {
	Password           string   `yaml:"password" env:"ENCRYPTION_PASSWORD"`
	KeyFile            string   `yaml:"key_file" env:"ENCRYPTION_KEY_FILE"`
	PreferredAlgorithm string   `yaml:"preferred_algorithm" env:"ENCRYPTION_PREFERRED_ALGORITHM"`
	SupportedAlgorithms []string `yaml:"supported_algorithms" env:"ENCRYPTION_SUPPORTED_ALGORITHMS"`
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
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	Enabled bool          `yaml:"enabled" env:"RATE_LIMIT_ENABLED"`
	Limit   int           `yaml:"limit" env:"RATE_LIMIT_REQUESTS"`
	Window  time.Duration `yaml:"window" env:"RATE_LIMIT_WINDOW"`
}

// LoadConfig loads configuration from a file and environment variables.
func LoadConfig(path string) (*Config, error) {
	config := &Config{
		ListenAddr: ":8080",
		LogLevel:   "info",
		Backend: BackendConfig{
			Endpoint: "https://s3.amazonaws.com",
			Provider: "aws",
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
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
			MaxHeaderBytes:    1 << 20, // 1MB
		},
		RateLimit: RateLimitConfig{
			Enabled: false,
			Limit:   100,
			Window:  60 * time.Second,
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

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
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
	if v := os.Getenv("ENCRYPTION_PASSWORD"); v != "" {
		config.Encryption.Password = v
	}
	if v := os.Getenv("ENCRYPTION_KEY_FILE"); v != "" {
		config.Encryption.KeyFile = v
	}
	if v := os.Getenv("ENCRYPTION_PREFERRED_ALGORITHM"); v != "" {
		config.Encryption.PreferredAlgorithm = v
	}
	// Note: Supported algorithms from env would need custom parsing (comma-separated)
	// For now, we'll leave it to config file
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
}

// Validate validates the configuration and returns an error if invalid.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}

	if c.Backend.Endpoint == "" {
		return fmt.Errorf("backend.endpoint is required")
	}

	if c.Backend.AccessKey == "" {
		return fmt.Errorf("backend.access_key is required")
	}

	if c.Backend.SecretKey == "" {
		return fmt.Errorf("backend.secret_key is required")
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

	return nil
}
