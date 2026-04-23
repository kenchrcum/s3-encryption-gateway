package harness

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/kenneth/s3-encryption-gateway/internal/api"
	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/kenneth/s3-encryption-gateway/internal/metrics"
	"github.com/kenneth/s3-encryption-gateway/internal/middleware"
	"github.com/kenneth/s3-encryption-gateway/internal/mpu"
	"github.com/kenneth/s3-encryption-gateway/internal/s3"
	"github.com/kenneth/s3-encryption-gateway/test/provider"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// Gateway represents a running in-process gateway server.
// All test interaction with the gateway should go through the URL field.
type Gateway struct {
	// URL is the base HTTP address of the gateway, e.g. "http://127.0.0.1:41523".
	URL    string
	// Addr is the host:port the gateway is listening on.
	Addr   string
	// Metrics is the Prometheus registry used by this gateway instance.
	// Conformance tests can query it to assert metric emission.
	Metrics *prometheus.Registry

	server   *http.Server
	listener net.Listener
}

// headObjectOverrideClient wraps an s3.Client and overrides Content-Length in
// HeadObject responses when the provided fn returns a non-nil value.
type headObjectOverrideClient struct {
	s3.Client
	fn func(bucket, key string) *int64
}

func (c *headObjectOverrideClient) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	meta, err := c.Client.HeadObject(ctx, bucket, key, versionID)
	if err != nil || meta == nil {
		return meta, err
	}
	if override := c.fn(bucket, key); override != nil {
		cp := make(map[string]string, len(meta)+1)
		for k, v := range meta {
			cp[k] = v
		}
		cp["Content-Length"] = fmt.Sprintf("%d", *override)
		return cp, nil
	}
	return meta, nil
}

// StartGateway starts an in-process gateway configured to talk to inst and
// registers t.Cleanup to shut it down. The backend named in inst is already
// running; this function only starts the gateway process.
func StartGateway(t *testing.T, inst provider.Instance, opts ...Option) *Gateway {
	t.Helper()

	o := &options{
		encryptionPassword: "test-encryption-password-123456",
		logLevel:           "error",
	}
	for _, opt := range opts {
		opt(o)
	}

	// Build the config from the provider instance.
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		LogLevel:   o.logLevel,
		Backend: config.BackendConfig{
			Endpoint:     inst.Endpoint,
			Region:       inst.Region,
			AccessKey:    inst.AccessKey,
			SecretKey:    inst.SecretKey,
			Provider:     inst.ProviderName,
			UseSSL:       false,
			UsePathStyle: true,
		},
		Encryption: config.EncryptionConfig{
			Password: o.encryptionPassword,
		},
		Compression: config.CompressionConfig{
			Enabled:   o.compressionEnabled,
			Algorithm: o.compressionAlgo,
		},
	}

	// Apply optional config mutator last.
	if o.extraConfig != nil {
		o.extraConfig(cfg)
	}

	// Network listener on a random free port.
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		t.Fatalf("harness.StartGateway: listen: %v", err)
	}

	addr := listener.Addr().String()
	url := "http://" + addr

	// Logger.
	logger := logrus.New()
	if lvl, err := logrus.ParseLevel(o.logLevel); err == nil {
		logger.SetLevel(lvl)
	} else {
		logger.SetLevel(logrus.ErrorLevel)
	}

	// Prometheus registry (isolated per test to avoid cross-test pollution).
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)

	// S3 backend client.
	// V0.6-PERF-2: use NewClientFactory so the retry policy and optional
	// fault-injection transport are both wired in.
	var s3Client s3.Client
	if !cfg.Backend.UseClientCredentials {
		factoryOpts := []s3.ClientFactoryOption{s3.WithMetrics(m)}
		if o.backendTransport != nil {
			factoryOpts = append(factoryOpts, s3.WithHTTPTransport(o.backendTransport))
		}
		factory := s3.NewClientFactory(&cfg.Backend, factoryOpts...)
		s3Client, err = factory.GetClient()
		if err != nil {
			listener.Close()
			t.Fatalf("harness.StartGateway: create S3 client: %v", err)
		}
		if o.headObjectOverride != nil {
			s3Client = &headObjectOverrideClient{Client: s3Client, fn: o.headObjectOverride}
		}
	}

	// Encryption engine.
	var compressionEngine crypto.CompressionEngine
	if cfg.Compression.Enabled {
		compressionEngine = crypto.NewCompressionEngine(
			cfg.Compression.Enabled,
			cfg.Compression.MinSize,
			cfg.Compression.ContentTypes,
			cfg.Compression.Algorithm,
			cfg.Compression.Level,
		)
	}

	encryptionEngine, err := crypto.NewEngineWithCompression(o.encryptionPassword, compressionEngine)
	if err != nil {
		listener.Close()
		t.Fatalf("harness.StartGateway: create encryption engine: %v", err)
	}
	// Wire the KeyManager into the encryption engine so that regular PUT/GET
	// operations use envelope encryption (KMS wrap/unwrap) and not just the
	// password-derived key. Without this, WithKeyManager only affects the MPU
	// path; the default engine would silently fall back to password-based mode.
	if o.keyManager != nil {
		crypto.SetKeyManager(encryptionEngine, o.keyManager)
	}

	// Encrypted-MPU: if valkeyAddr is set without an explicit mpuStore,
	// construct a ValkeyStateStore (plaintext allowed — test containers).
	if o.valkeyAddr != "" && o.mpuStore == nil {
		store, storeErr := mpu.NewValkeyStateStore(context.Background(), config.ValkeyConfig{
			Addr:                   o.valkeyAddr,
			InsecureAllowPlaintext: true,
			TLS:                    config.ValkeyTLSConfig{Enabled: false},
			TTLSeconds:             3600,
			DialTimeout:            2 * time.Second,
			ReadTimeout:            1 * time.Second,
			WriteTimeout:           1 * time.Second,
			PoolSize:               4,
		})
		if storeErr != nil {
			listener.Close()
			t.Fatalf("harness.StartGateway: create Valkey state store (%s): %v", o.valkeyAddr, storeErr)
		}
		o.mpuStore = store
		t.Cleanup(func() { _ = store.Close() })
	}

	// Encrypted-MPU: if a bucket glob is configured, build a PolicyManager
	// with EncryptMultipartUploads=true for that glob (unless caller already
	// provided one).
	if o.encryptedMPUBucket != "" && o.policyManager == nil {
		policyDir := t.TempDir()
		policyYAML := fmt.Sprintf("id: harness-enc-mpu\nbuckets:\n  - %q\nencrypt_multipart_uploads: true\n",
			o.encryptedMPUBucket)
		policyPath := filepath.Join(policyDir, "policy.yaml")
		if err := os.WriteFile(policyPath, []byte(policyYAML), 0600); err != nil {
			listener.Close()
			t.Fatalf("harness.StartGateway: write MPU policy file: %v", err)
		}
		pm := config.NewPolicyManager()
		if err := pm.LoadPolicies([]string{policyPath}); err != nil {
			listener.Close()
			t.Fatalf("harness.StartGateway: load MPU policy: %v", err)
		}
		o.policyManager = pm
	}

	// When encrypted MPU is active a KeyManager is required for DEK wrap/unwrap.
	// Default to the password-derived KeyManager if none was supplied.
	if o.mpuStore != nil && o.keyManager == nil {
		km, kmErr := crypto.NewPasswordKeyManager(o.encryptionPassword)
		if kmErr != nil {
			listener.Close()
			t.Fatalf("harness.StartGateway: create password KeyManager: %v", kmErr)
		}
		o.keyManager = km
	}

	// API handler.
	handler := api.NewHandlerWithFeatures(
		s3Client, encryptionEngine, logger, m,
		o.keyManager, nil, o.auditLogger, cfg, o.policyManager,
	)
	if o.mpuStore != nil {
		handler.WithMPUStateStore(o.mpuStore)
	}

	// Router.
	router := mux.NewRouter()
	router.Handle("/metrics", m.Handler()).Methods("GET")
	handler.RegisterRoutes(router)

	// Middleware.
	httpHandler := middleware.RecoveryMiddleware(logger)(router)
	httpHandler = middleware.LoggingMiddleware(logger, &cfg.Logging)(httpHandler)

	// HTTP server.
	server := &http.Server{
		Addr:              addr,
		Handler:           httpHandler,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Logf("harness gateway server error: %v", err)
		}
	}()

	// Wait for the gateway to be ready.
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for {
		select {
		case <-waitCtx.Done():
			listener.Close()
			t.Fatal("harness.StartGateway: timeout waiting for gateway to become ready")
		default:
			resp, err := http.Get(url + "/health")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					goto ready
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

ready:
	gw := &Gateway{
		URL:      url,
		Addr:     addr,
		Metrics:  reg,
		server:   server,
		listener: listener,
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx) //nolint:errcheck
		listener.Close()
	})

	return gw
}

// HTTPClient returns a plain *http.Client suitable for issuing requests to the
// gateway. The client has a 30-second timeout and follows redirects.
func (g *Gateway) HTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}
