package test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/kenneth/s3-encryption-gateway/internal/api"
	"github.com/kenneth/s3-encryption-gateway/internal/audit"
	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/kenneth/s3-encryption-gateway/internal/metrics"
	"github.com/kenneth/s3-encryption-gateway/internal/middleware"
	"github.com/kenneth/s3-encryption-gateway/internal/mpu"
	"github.com/kenneth/s3-encryption-gateway/internal/s3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// TestGateway represents a running gateway server for testing.
type TestGateway struct {
	Addr     string
	URL      string
	server   *http.Server
	client   *http.Client
	listener net.Listener
}

// testGatewayOpts holds optional dependencies for StartGateway.
type testGatewayOpts struct {
	policyManager      *config.PolicyManager
	keyManager         crypto.KeyManager
	mpuStore           mpu.StateStore
	auditLogger        audit.Logger
	headObjectOverride func(bucket, key string) *int64 // returns non-nil to override Content-Length
}

// TestGatewayOption is a functional option for StartGateway.
type TestGatewayOption func(*testGatewayOpts)

// WithPolicyManager wires a per-bucket policy manager into the gateway.
func WithPolicyManager(pm *config.PolicyManager) TestGatewayOption {
	return func(o *testGatewayOpts) { o.policyManager = pm }
}

// WithKeyManager wires a KeyManager (for MPU DEK wrap/unwrap) into the gateway.
func WithKeyManager(km crypto.KeyManager) TestGatewayOption {
	return func(o *testGatewayOpts) { o.keyManager = km }
}

// WithMPUStateStore wires a Valkey state store into the gateway.
func WithMPUStateStore(store mpu.StateStore) TestGatewayOption {
	return func(o *testGatewayOpts) { o.mpuStore = store }
}

// WithAuditLogger wires an audit logger into the gateway.
func WithAuditLogger(al audit.Logger) TestGatewayOption {
	return func(o *testGatewayOpts) { o.auditLogger = al }
}

// WithHeadObjectOverride wires a hook that overrides the Content-Length
// returned by HeadObject for specific (bucket, key) pairs. Use this to
// simulate large objects (> 5 GiB) without actually uploading them.
// fn must return nil to leave Content-Length unmodified.
func WithHeadObjectOverride(fn func(bucket, key string) *int64) TestGatewayOption {
	return func(o *testGatewayOpts) { o.headObjectOverride = fn }
}

// StartGateway starts a gateway server for testing.
// The variadic opts parameter accepts TestGatewayOption values; all existing
// callers that pass no options continue to compile and behave identically.
func StartGateway(t *testing.T, cfg *config.Config, opts ...TestGatewayOption) *TestGateway {
	t.Helper()

	o := &testGatewayOpts{}
	for _, opt := range opts {
		opt(o)
	}

	// Find available port
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		t.Fatalf("Failed to listen on %s: %v", cfg.ListenAddr, err)
	}

	addr := listener.Addr().String()
	url := "http://" + addr

	// Initialize logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Only errors in tests

	// Initialize metrics with custom registry to avoid conflicts between tests
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)

	// Initialize S3 client (only if useClientCredentials is not enabled)
	var s3Client s3.Client
	if !cfg.Backend.UseClientCredentials {
		var innerErr error
		s3Client, innerErr = s3.NewClient(&cfg.Backend)
		if innerErr != nil {
			listener.Close()
			t.Fatalf("Failed to create S3 client: %v", innerErr)
		}
		if o.headObjectOverride != nil {
			s3Client = &headObjectOverrideClient{Client: s3Client, fn: o.headObjectOverride}
		}
	}

	// Initialize encryption engine
	encryptionPassword := cfg.Encryption.Password
	if encryptionPassword == "" {
		encryptionPassword = "test-password-123456"
	}

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

	encryptionEngine, err := crypto.NewEngineWithCompression(encryptionPassword, compressionEngine)
	if err != nil {
		listener.Close()
		t.Fatalf("Failed to create encryption engine: %v", err)
	}

	// Initialize API handler with config support (required for useClientCredentials)
	handler := api.NewHandlerWithFeatures(s3Client, encryptionEngine, logger, m,
		o.keyManager, nil, o.auditLogger, cfg, o.policyManager)

	if o.mpuStore != nil {
		handler.WithMPUStateStore(o.mpuStore)
	}

	// Setup router
	router := mux.NewRouter()

	// Register metrics endpoint
	router.Handle("/metrics", m.Handler()).Methods("GET")

	// Register API routes
	handler.RegisterRoutes(router)

	// Apply middleware
	httpHandler := middleware.RecoveryMiddleware(logger)(router)
	httpHandler = middleware.LoggingMiddleware(logger, &cfg.Logging)(httpHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:              addr,
		Handler:           httpHandler,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}

	// Start server in goroutine
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()

	// Wait for server to be ready
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			listener.Close()
			t.Fatal("Timeout waiting for gateway to start")
		default:
			resp, err := http.Get(url + "/health")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					goto ready
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

ready:
	// Create HTTP client
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	return &TestGateway{
		Addr:     addr,
		URL:      url,
		server:   server,
		client:   client,
		listener: listener,
	}
}

// headObjectOverrideClient wraps an s3.Client and overrides Content-Length in
// HeadObject responses when the provided fn returns a non-nil value. This is
// used to simulate objects larger than 5 GiB without uploading real data.
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

// Close shuts down the gateway server.
func (g *TestGateway) Close() {
	if g.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		g.server.Shutdown(ctx)
	}
	if g.listener != nil {
		g.listener.Close()
	}
}

// GetHTTPClient returns the HTTP client for making requests.
func (g *TestGateway) GetHTTPClient() *http.Client {
	return g.client
}
