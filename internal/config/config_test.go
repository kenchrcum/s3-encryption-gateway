package config

import (
	"os"
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	// Set minimal required environment variables for test
	os.Setenv("BACKEND_ACCESS_KEY", "test-key")
	os.Setenv("BACKEND_SECRET_KEY", "test-secret")
	os.Setenv("ENCRYPTION_PASSWORD", "test-password")
	defer func() {
		os.Unsetenv("BACKEND_ACCESS_KEY")
		os.Unsetenv("BACKEND_SECRET_KEY")
		os.Unsetenv("ENCRYPTION_PASSWORD")
	}()

	config, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.ListenAddr != ":8080" {
		t.Errorf("expected ListenAddr :8080, got %s", config.ListenAddr)
	}

	if config.LogLevel != "info" {
		t.Errorf("expected LogLevel info, got %s", config.LogLevel)
	}

	// Provider is now optional, just for reference
}

func TestLoadConfig_EnvOverrides(t *testing.T) {
	os.Setenv("LISTEN_ADDR", ":9090")
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("BACKEND_ENDPOINT", "http://localhost:9000")
	os.Setenv("BACKEND_ACCESS_KEY", "test-key")
	os.Setenv("BACKEND_SECRET_KEY", "test-secret")
	os.Setenv("ENCRYPTION_PASSWORD", "test-password")

	defer func() {
		os.Unsetenv("LISTEN_ADDR")
		os.Unsetenv("LOG_LEVEL")
		os.Unsetenv("BACKEND_ENDPOINT")
		os.Unsetenv("BACKEND_ACCESS_KEY")
		os.Unsetenv("BACKEND_SECRET_KEY")
		os.Unsetenv("ENCRYPTION_PASSWORD")
	}()

	config, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.ListenAddr != ":9090" {
		t.Errorf("expected ListenAddr :9090, got %s", config.ListenAddr)
	}

	if config.LogLevel != "debug" {
		t.Errorf("expected LogLevel debug, got %s", config.LogLevel)
	}

	if config.Backend.Endpoint != "http://localhost:9000" {
		t.Errorf("expected Backend.Endpoint http://localhost:9000, got %s", config.Backend.Endpoint)
	}
}

// TestLoadConfig_ValkeyEnvOverrides verifies the V0.6-SEC-3 / #14 env var
// bindings for the Helm chart's Valkey subchart wiring.
func TestLoadConfig_ValkeyEnvOverrides(t *testing.T) {
	t.Setenv("ENCRYPTION_PASSWORD", "test-password-12345")
	t.Setenv("BACKEND_ENDPOINT", "http://localhost:9000")
	t.Setenv("BACKEND_ACCESS_KEY", "test-key")
	t.Setenv("BACKEND_SECRET_KEY", "test-secret")
	t.Setenv("VALKEY_ADDR", "valkey.prod.svc:6379")
	t.Setenv("VALKEY_USERNAME", "default")
	t.Setenv("VALKEY_PASSWORD_ENV", "VALKEY_PW")
	t.Setenv("VALKEY_DB", "3")
	t.Setenv("VALKEY_TLS_ENABLED", "true")
	t.Setenv("VALKEY_TLS_CA_FILE", "/etc/tls/ca.pem")
	t.Setenv("VALKEY_TLS_CERT_FILE", "/etc/tls/cert.pem")
	t.Setenv("VALKEY_TLS_KEY_FILE", "/etc/tls/key.pem")
	t.Setenv("VALKEY_TLS_INSECURE_SKIP_VERIFY", "false")
	t.Setenv("VALKEY_INSECURE_ALLOW_PLAINTEXT", "false")
	t.Setenv("VALKEY_TTL_SECONDS", "86400")
	t.Setenv("VALKEY_POOL_SIZE", "32")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.MultipartState.Valkey.Addr != "valkey.prod.svc:6379" {
		t.Errorf("expected Valkey.Addr valkey.prod.svc:6379, got %s", cfg.MultipartState.Valkey.Addr)
	}
	if cfg.MultipartState.Valkey.Username != "default" {
		t.Errorf("expected Username 'default', got %q", cfg.MultipartState.Valkey.Username)
	}
	if cfg.MultipartState.Valkey.DB != 3 {
		t.Errorf("expected DB 3, got %d", cfg.MultipartState.Valkey.DB)
	}
	if !cfg.MultipartState.Valkey.TLS.Enabled {
		t.Errorf("expected TLS.Enabled=true, got false")
	}
	if cfg.MultipartState.Valkey.TLS.CAFile != "/etc/tls/ca.pem" {
		t.Errorf("expected TLS.CAFile /etc/tls/ca.pem, got %q", cfg.MultipartState.Valkey.TLS.CAFile)
	}
	if cfg.MultipartState.Valkey.TLS.CertFile != "/etc/tls/cert.pem" {
		t.Errorf("expected TLS.CertFile /etc/tls/cert.pem, got %q", cfg.MultipartState.Valkey.TLS.CertFile)
	}
	if cfg.MultipartState.Valkey.InsecureAllowPlaintext {
		t.Errorf("expected InsecureAllowPlaintext=false, got true")
	}
	if cfg.MultipartState.Valkey.TTLSeconds != 86400 {
		t.Errorf("expected TTLSeconds 86400, got %d", cfg.MultipartState.Valkey.TTLSeconds)
	}
	if cfg.MultipartState.Valkey.PoolSize != 32 {
		t.Errorf("expected PoolSize 32, got %d", cfg.MultipartState.Valkey.PoolSize)
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				ListenAddr: ":8080",
				Backend: BackendConfig{
					Endpoint:  "http://localhost:9000",
					AccessKey: "test-key",
					SecretKey: "test-secret",
				},
				Encryption: EncryptionConfig{
					Password: "test-password",
				},
			},
			wantErr: false,
		},
		{
			name: "missing listen addr",
			config: &Config{
				Backend: BackendConfig{
					Endpoint:  "http://localhost:9000",
					AccessKey: "test-key",
					SecretKey: "test-secret",
				},
				Encryption: EncryptionConfig{
					Password: "test-password",
				},
			},
			wantErr: true,
		},
		{
			name: "missing backend endpoint",
			config: &Config{
				ListenAddr: ":8080",
				Backend: BackendConfig{
					AccessKey: "test-key",
					SecretKey: "test-secret",
				},
				Encryption: EncryptionConfig{
					Password: "test-password",
				},
			},
			wantErr: false, // Endpoint is optional - empty means AWS default
		},
		{
			name: "missing encryption password",
			config: &Config{
				ListenAddr: ":8080",
				Backend: BackendConfig{
					Endpoint:  "http://localhost:9000",
					AccessKey: "test-key",
					SecretKey: "test-secret",
				},
				Encryption: EncryptionConfig{},
			},
			wantErr: true,
		},
		{
			name: "useClientCredentials enabled - backend credentials not required",
			config: &Config{
				ListenAddr: ":8080",
				Backend: BackendConfig{
					Endpoint:             "http://localhost:9000",
					UseClientCredentials: true,
					// AccessKey and SecretKey are empty - this is valid
				},
				Encryption: EncryptionConfig{
					Password: "test-password",
				},
			},
			wantErr: false,
		},
		{
			name: "useClientCredentials disabled - backend credentials required",
			config: &Config{
				ListenAddr: ":8080",
				Backend: BackendConfig{
					Endpoint:             "http://localhost:9000",
					UseClientCredentials: false,
					// Missing AccessKey and SecretKey
				},
				Encryption: EncryptionConfig{
					Password: "test-password",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
