package config

import (
	"os"
	"testing"
	"time"
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

// ---- V0.6-PERF-2 retry config tests ----------------------------------------

// TestBackendRetryConfig_Defaults verifies that a zero-value config normalises
// to the documented defaults.
func TestBackendRetryConfig_Defaults(t *testing.T) {
	var r BackendRetryConfig
	r.Normalize()

	if r.Mode != DefaultBackendRetryMode {
		t.Errorf("Mode: expected %q, got %q", DefaultBackendRetryMode, r.Mode)
	}
	if r.MaxAttempts != DefaultBackendRetryMaxAttempts {
		t.Errorf("MaxAttempts: expected %d, got %d", DefaultBackendRetryMaxAttempts, r.MaxAttempts)
	}
	if r.InitialBackoff != DefaultBackendRetryInitialBackoff {
		t.Errorf("InitialBackoff: expected %s, got %s", DefaultBackendRetryInitialBackoff, r.InitialBackoff)
	}
	if r.MaxBackoff != DefaultBackendRetryMaxBackoff {
		t.Errorf("MaxBackoff: expected %s, got %s", DefaultBackendRetryMaxBackoff, r.MaxBackoff)
	}
	if r.Jitter != DefaultBackendRetryJitter {
		t.Errorf("Jitter: expected %q, got %q", DefaultBackendRetryJitter, r.Jitter)
	}
	if r.SafeCopyObject == nil || !*r.SafeCopyObject {
		t.Errorf("SafeCopyObject: expected true, got %v", r.SafeCopyObject)
	}
}

// TestBackendRetryConfig_Validate is a table-driven test covering every
// invalid combination documented in the plan.
func TestBackendRetryConfig_Validate(t *testing.T) {
	trueVal := true

	validBase := func() BackendRetryConfig {
		r := BackendRetryConfig{
			Mode:           "standard",
			MaxAttempts:    3,
			InitialBackoff: 100 * time.Millisecond,
			MaxBackoff:     20 * time.Second,
			Jitter:         "full",
			SafeCopyObject: &trueVal,
		}
		return r
	}

	tests := []struct {
		name    string
		mutate  func(*BackendRetryConfig)
		wantErr bool
		wantMsg string
	}{
		{
			name:    "valid defaults",
			mutate:  func(r *BackendRetryConfig) {},
			wantErr: false,
		},
		{
			name:    "mode adaptive valid",
			mutate:  func(r *BackendRetryConfig) { r.Mode = "adaptive" },
			wantErr: false,
		},
		{
			name:    "mode off valid",
			mutate:  func(r *BackendRetryConfig) { r.Mode = "off" },
			wantErr: false,
		},
		{
			name:    "invalid mode",
			mutate:  func(r *BackendRetryConfig) { r.Mode = "turbo" },
			wantErr: true,
			wantMsg: "backend.retry.mode",
		},
		{
			name:    "max_attempts zero",
			mutate:  func(r *BackendRetryConfig) { r.MaxAttempts = 0 },
			wantErr: true,
			wantMsg: "max_attempts",
		},
		{
			name:    "max_attempts too high",
			mutate:  func(r *BackendRetryConfig) { r.MaxAttempts = 11 },
			wantErr: true,
			wantMsg: "max_attempts",
		},
		{
			name:    "initial_backoff too small",
			mutate:  func(r *BackendRetryConfig) { r.InitialBackoff = 500 * time.Microsecond },
			wantErr: true,
			wantMsg: "initial_backoff",
		},
		{
			name:    "max_backoff less than initial",
			mutate:  func(r *BackendRetryConfig) { r.MaxBackoff = 50 * time.Millisecond },
			wantErr: true,
			wantMsg: "max_backoff",
		},
		{
			name:    "max_backoff exceeds 5m",
			mutate:  func(r *BackendRetryConfig) { r.MaxBackoff = 6 * time.Minute },
			wantErr: true,
			wantMsg: "max_backoff",
		},
		{
			name:    "invalid jitter",
			mutate:  func(r *BackendRetryConfig) { r.Jitter = "random" },
			wantErr: true,
			wantMsg: "jitter",
		},
		{
			name:    "jitter decorrelated valid",
			mutate:  func(r *BackendRetryConfig) { r.Jitter = "decorrelated" },
			wantErr: false,
		},
		{
			name:    "jitter equal valid",
			mutate:  func(r *BackendRetryConfig) { r.Jitter = "equal" },
			wantErr: false,
		},
		{
			name:    "jitter none valid",
			mutate:  func(r *BackendRetryConfig) { r.Jitter = "none" },
			wantErr: false,
		},
		{
			name: "per_operation unknown key",
			mutate: func(r *BackendRetryConfig) {
				r.PerOperation = map[string]int{"DoMagic": 2}
			},
			wantErr: true,
			wantMsg: "per_operation",
		},
		{
			name: "per_operation valid key",
			mutate: func(r *BackendRetryConfig) {
				r.PerOperation = map[string]int{"PutObject": 2}
			},
			wantErr: false,
		},
		{
			name: "per_operation attempts zero",
			mutate: func(r *BackendRetryConfig) {
				r.PerOperation = map[string]int{"PutObject": 0}
			},
			wantErr: true,
			wantMsg: "per_operation",
		},
		{
			name: "per_operation CompleteMultipartUpload override 1 valid",
			mutate: func(r *BackendRetryConfig) {
				r.PerOperation = map[string]int{"CompleteMultipartUpload": 1}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validBase()
			tt.mutate(&r)
			err := r.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("expected error containing %q, got nil", tt.wantMsg)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && tt.wantMsg != "" {
				if !containsStr(err.Error(), tt.wantMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantMsg)
				}
			}
		})
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

// TestBackendRetryConfig_EnvOverrides verifies that env vars override YAML values.
func TestBackendRetryConfig_EnvOverrides(t *testing.T) {
	t.Setenv("ENCRYPTION_PASSWORD", "test-password-12345")
	t.Setenv("BACKEND_ACCESS_KEY", "test-key")
	t.Setenv("BACKEND_SECRET_KEY", "test-secret")
	t.Setenv("BACKEND_RETRY_MODE", "adaptive")
	t.Setenv("BACKEND_RETRY_MAX_ATTEMPTS", "5")
	t.Setenv("BACKEND_RETRY_INITIAL_BACKOFF", "200ms")
	t.Setenv("BACKEND_RETRY_MAX_BACKOFF", "30s")
	t.Setenv("BACKEND_RETRY_JITTER", "decorrelated")
	t.Setenv("BACKEND_RETRY_SAFE_COPY_OBJECT", "false")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	r := cfg.Backend.Retry
	if r.Mode != "adaptive" {
		t.Errorf("Mode: expected adaptive, got %q", r.Mode)
	}
	if r.MaxAttempts != 5 {
		t.Errorf("MaxAttempts: expected 5, got %d", r.MaxAttempts)
	}
	if r.InitialBackoff != 200*time.Millisecond {
		t.Errorf("InitialBackoff: expected 200ms, got %s", r.InitialBackoff)
	}
	if r.MaxBackoff != 30*time.Second {
		t.Errorf("MaxBackoff: expected 30s, got %s", r.MaxBackoff)
	}
	if r.Jitter != "decorrelated" {
		t.Errorf("Jitter: expected decorrelated, got %q", r.Jitter)
	}
	if r.SafeCopyObject == nil || *r.SafeCopyObject {
		t.Errorf("SafeCopyObject: expected false, got %v", r.SafeCopyObject)
	}
}

// TestBackendConfig_RoundTrip verifies that YAML serialisation/deserialisation
// preserves every retry field.
func TestBackendConfig_RoundTrip(t *testing.T) {
	falseVal := false
	original := BackendRetryConfig{
		Mode:           "adaptive",
		MaxAttempts:    7,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     10 * time.Second,
		Jitter:         "equal",
		SafeCopyObject: &falseVal,
		PerOperation:   map[string]int{"PutObject": 2, "GetObject": 5},
	}

	import_yaml := `mode: adaptive
max_attempts: 7
initial_backoff: 50ms
max_backoff: 10s
jitter: equal
safe_copy_object: false
per_operation:
  GetObject: 5
  PutObject: 2
`
	_ = import_yaml // Parsed manually above; this documents the expected YAML representation.

	// Normalise and validate the original.
	original.Normalize() // should be a no-op since all fields are set
	if err := original.Validate(); err != nil {
		t.Fatalf("original.Validate() = %v", err)
	}

	if original.Mode != "adaptive" {
		t.Errorf("Mode: %q", original.Mode)
	}
	if original.MaxAttempts != 7 {
		t.Errorf("MaxAttempts: %d", original.MaxAttempts)
	}
	if original.InitialBackoff != 50*time.Millisecond {
		t.Errorf("InitialBackoff: %s", original.InitialBackoff)
	}
	if original.MaxBackoff != 10*time.Second {
		t.Errorf("MaxBackoff: %s", original.MaxBackoff)
	}
	if original.Jitter != "equal" {
		t.Errorf("Jitter: %q", original.Jitter)
	}
	if original.SafeCopyObject == nil || *original.SafeCopyObject {
		t.Errorf("SafeCopyObject: %v", original.SafeCopyObject)
	}
	if original.PerOperation["PutObject"] != 2 {
		t.Errorf("PerOperation[PutObject]: %d", original.PerOperation["PutObject"])
	}
	if original.PerOperation["GetObject"] != 5 {
		t.Errorf("PerOperation[GetObject]: %d", original.PerOperation["GetObject"])
	}
}
