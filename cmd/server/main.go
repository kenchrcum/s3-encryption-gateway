package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/kenneth/s3-encryption-gateway/internal/api"
	"github.com/kenneth/s3-encryption-gateway/internal/audit"
	"github.com/kenneth/s3-encryption-gateway/internal/cache"
	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/kenneth/s3-encryption-gateway/internal/debug"
	"github.com/kenneth/s3-encryption-gateway/internal/metrics"
	"github.com/kenneth/s3-encryption-gateway/internal/middleware"
	"github.com/kenneth/s3-encryption-gateway/internal/s3"
	"github.com/sirupsen/logrus"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

var (
	version = "dev"
	commit  = "unknown"
)

// ConfigChangeApplier holds references to components that can be updated during hot reload
type ConfigChangeApplier struct {
	logger         *logrus.Logger
	tracerProvider *sdktrace.TracerProvider
	RateLimiter    *middleware.RateLimiter
	cache          cache.Cache
	auditLogger    audit.Logger
	config         *config.Config
}

// NewConfigChangeApplier creates a new applier for configuration changes
func NewConfigChangeApplier(logger *logrus.Logger, tracerProvider *sdktrace.TracerProvider, rateLimiter *middleware.RateLimiter, cache cache.Cache, auditLogger audit.Logger, initialConfig *config.Config) *ConfigChangeApplier {
	return &ConfigChangeApplier{
		logger:         logger,
		tracerProvider: tracerProvider,
		RateLimiter:    rateLimiter,
		cache:          cache,
		auditLogger:    auditLogger,
		config:         initialConfig,
	}
}

// ApplyConfigChanges applies non-crypto configuration changes to running components
func (a *ConfigChangeApplier) ApplyConfigChanges(oldConfig, newConfig *config.Config) error {
	changes := []string{}

	// Update log level
	if oldConfig.LogLevel != newConfig.LogLevel {
		level, err := logrus.ParseLevel(newConfig.LogLevel)
		if err != nil {
			a.logger.WithError(err).Warn("Invalid log level in reloaded config, keeping current level")
		} else {
			a.logger.SetLevel(level)
			debug.InitFromLogLevel(newConfig.LogLevel)
			changes = append(changes, fmt.Sprintf("log_level: %s -> %s", oldConfig.LogLevel, newConfig.LogLevel))
		}
	}

	// Update rate limiting
	if oldConfig.RateLimit.Enabled != newConfig.RateLimit.Enabled ||
		oldConfig.RateLimit.Limit != newConfig.RateLimit.Limit ||
		oldConfig.RateLimit.Window != newConfig.RateLimit.Window {

		if a.RateLimiter != nil {
			a.RateLimiter.Stop()
		}

		if newConfig.RateLimit.Enabled {
			a.RateLimiter = middleware.NewRateLimiter(
				newConfig.RateLimit.Limit,
				newConfig.RateLimit.Window,
				a.logger,
			)
			changes = append(changes, fmt.Sprintf("rate_limit: enabled=%v, limit=%d, window=%v",
				newConfig.RateLimit.Enabled, newConfig.RateLimit.Limit, newConfig.RateLimit.Window))
		} else {
			a.RateLimiter = nil
			changes = append(changes, "rate_limit: disabled")
		}
	}

	// Update cache settings
	if oldConfig.Cache.Enabled != newConfig.Cache.Enabled ||
		oldConfig.Cache.MaxSize != newConfig.Cache.MaxSize ||
		oldConfig.Cache.MaxItems != newConfig.Cache.MaxItems ||
		oldConfig.Cache.DefaultTTL != newConfig.Cache.DefaultTTL {

		// Note: Cache reconfiguration is complex and may not be safe for existing entries
		// For now, we'll log the change but not apply it
		a.logger.WithFields(logrus.Fields{
			"old_enabled":   oldConfig.Cache.Enabled,
			"new_enabled":   newConfig.Cache.Enabled,
			"old_max_size":  oldConfig.Cache.MaxSize,
			"new_max_size":  newConfig.Cache.MaxSize,
			"old_max_items": oldConfig.Cache.MaxItems,
			"new_max_items": newConfig.Cache.MaxItems,
			"old_ttl":       oldConfig.Cache.DefaultTTL,
			"new_ttl":       newConfig.Cache.DefaultTTL,
		}).Warn("Cache configuration changed - restart required for changes to take effect")

		changes = append(changes, "cache: configuration changed (restart required)")
	}

	// Update audit settings
	if oldConfig.Audit.Enabled != newConfig.Audit.Enabled ||
		oldConfig.Audit.MaxEvents != newConfig.Audit.MaxEvents {

		// Note: Changing audit settings during runtime is complex
		// For now, we'll log the change but not apply it
		a.logger.WithFields(logrus.Fields{
			"old_enabled":    oldConfig.Audit.Enabled,
			"new_enabled":    newConfig.Audit.Enabled,
			"old_max_events": oldConfig.Audit.MaxEvents,
			"new_max_events": newConfig.Audit.MaxEvents,
		}).Warn("Audit configuration changed - restart required for changes to take effect")

		changes = append(changes, "audit: configuration changed (restart required)")
	}

	// Update tracing settings
	if oldConfig.Tracing.Enabled != newConfig.Tracing.Enabled ||
		oldConfig.Tracing.ServiceName != newConfig.Tracing.ServiceName ||
		oldConfig.Tracing.ServiceVersion != newConfig.Tracing.ServiceVersion ||
		oldConfig.Tracing.Exporter != newConfig.Tracing.Exporter ||
		oldConfig.Tracing.JaegerEndpoint != newConfig.Tracing.JaegerEndpoint ||
		oldConfig.Tracing.OtlpEndpoint != newConfig.Tracing.OtlpEndpoint ||
		oldConfig.Tracing.SamplingRatio != newConfig.Tracing.SamplingRatio ||
		oldConfig.Tracing.RedactSensitive != newConfig.Tracing.RedactSensitive {

		// Tracing reconfiguration is complex and may require restarting the tracer provider
		a.logger.WithFields(logrus.Fields{
			"old_enabled": oldConfig.Tracing.Enabled,
			"new_enabled": newConfig.Tracing.Enabled,
		}).Warn("Tracing configuration changed - restart required for changes to take effect")

		changes = append(changes, "tracing: configuration changed (restart required)")
	}

	// Update proxied bucket
	if oldConfig.ProxiedBucket != newConfig.ProxiedBucket {
		a.logger.WithFields(logrus.Fields{
			"old_bucket": oldConfig.ProxiedBucket,
			"new_bucket": newConfig.ProxiedBucket,
		}).Warn("Proxied bucket changed - restart required for changes to take effect")

		changes = append(changes, fmt.Sprintf("proxied_bucket: %s -> %s (restart required)", oldConfig.ProxiedBucket, newConfig.ProxiedBucket))
	}

	// Update server timeouts (these require server restart, but we can log the change)
	if oldConfig.Server.ReadTimeout != newConfig.Server.ReadTimeout ||
		oldConfig.Server.WriteTimeout != newConfig.Server.WriteTimeout ||
		oldConfig.Server.IdleTimeout != newConfig.Server.IdleTimeout ||
		oldConfig.Server.ReadHeaderTimeout != newConfig.Server.ReadHeaderTimeout ||
		oldConfig.Server.MaxHeaderBytes != newConfig.Server.MaxHeaderBytes ||
		oldConfig.Server.DisableMultipartUploads != newConfig.Server.DisableMultipartUploads {

		a.logger.WithFields(logrus.Fields{
			"read_timeout":  newConfig.Server.ReadTimeout,
			"write_timeout": newConfig.Server.WriteTimeout,
			"idle_timeout":  newConfig.Server.IdleTimeout,
		}).Warn("Server configuration changed - restart required for changes to take effect")

		changes = append(changes, "server: timeouts/configuration changed (restart required)")
	}

	// Update logging configuration
	if oldConfig.Logging.AccessLogFormat != newConfig.Logging.AccessLogFormat ||
		len(oldConfig.Logging.RedactHeaders) != len(newConfig.Logging.RedactHeaders) {

		// Check if redact headers changed
		headersChanged := len(oldConfig.Logging.RedactHeaders) != len(newConfig.Logging.RedactHeaders)
		if !headersChanged {
			for i, header := range oldConfig.Logging.RedactHeaders {
				if i >= len(newConfig.Logging.RedactHeaders) || header != newConfig.Logging.RedactHeaders[i] {
					headersChanged = true
					break
				}
			}
		}

		if oldConfig.Logging.AccessLogFormat != newConfig.Logging.AccessLogFormat || headersChanged {
			a.logger.WithFields(logrus.Fields{
				"old_format": oldConfig.Logging.AccessLogFormat,
				"new_format": newConfig.Logging.AccessLogFormat,
			}).Warn("Logging configuration changed - restart required for changes to take effect")

			changes = append(changes, "logging: configuration changed (restart required)")
		}
	}

	// Update the config reference
	a.config = newConfig

	// Log all changes
	if len(changes) > 0 {
		a.logger.WithField("changes", changes).Info("Configuration reloaded with changes")
	} else {
		a.logger.Info("Configuration reloaded (no changes detected)")
	}

	return nil
}

// InitTracing initializes OpenTelemetry tracing based on configuration
func InitTracing(cfg config.TracingConfig, logger *logrus.Logger) (*sdktrace.TracerProvider, error) {
	// Create resource with service information
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create exporter based on configuration
	var exporter sdktrace.SpanExporter
	switch cfg.Exporter {
	case "stdout":
		exporter, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout exporter: %w", err)
		}
	case "jaeger":
		exporter, err = jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(cfg.JaegerEndpoint)))
		if err != nil {
			return nil, fmt.Errorf("failed to create jaeger exporter: %w", err)
		}
	case "otlp":
		exporter, err = otlptracegrpc.New(context.Background(),
			otlptracegrpc.WithEndpoint(cfg.OtlpEndpoint),
			otlptracegrpc.WithInsecure(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported exporter: %s", cfg.Exporter)
	}

	// Create sampler
	var sampler sdktrace.Sampler
	if cfg.SamplingRatio >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else if cfg.SamplingRatio <= 0.0 {
		sampler = sdktrace.NeverSample()
	} else {
		sampler = sdktrace.TraceIDRatioBased(cfg.SamplingRatio)
	}

	// Create tracer provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sampler),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(sdktrace.NewBatchSpanProcessor(exporter)),
	)

	// Set as global tracer provider
	otel.SetTracerProvider(tp)

	return tp, nil
}

func buildKeyManager(cfg *config.Config, logger *logrus.Logger) (crypto.KeyManager, error) {
	provider := strings.ToLower(cfg.Encryption.KeyManager.Provider)
	if provider == "" {
		provider = "cosmian"
	}

	switch provider {
	case "cosmian", "kmip":
		return newCosmianKeyManager(cfg.Encryption.KeyManager, logger)
	default:
		return nil, fmt.Errorf("unsupported key manager provider %q", provider)
	}
}

func newCosmianKeyManager(kmCfg config.KeyManagerConfig, logger *logrus.Logger) (crypto.KeyManager, error) {
	if kmCfg.Cosmian.Endpoint == "" {
		return nil, fmt.Errorf("cosmian.key_manager.endpoint is required")
	}
	if len(kmCfg.Cosmian.Keys) == 0 {
		return nil, fmt.Errorf("cosmian.key_manager.keys must include at least one wrapping key reference")
	}

	tlsCfg, err := buildCosmianTLSConfig(kmCfg.Cosmian)
	if err != nil {
		return nil, err
	}

	keyRefs := make([]crypto.KMIPKeyReference, 0, len(kmCfg.Cosmian.Keys))
	for i, key := range kmCfg.Cosmian.Keys {
		if key.ID == "" {
			return nil, fmt.Errorf("cosmian.key_manager.keys[%d].id is required", i)
		}
		version := key.Version
		if version == 0 {
			version = i + 1
		}
		keyRefs = append(keyRefs, crypto.KMIPKeyReference{
			ID:      key.ID,
			Version: version,
		})
	}

	opts := crypto.CosmianKMIPOptions{
		Endpoint:       kmCfg.Cosmian.Endpoint,
		Keys:           keyRefs,
		TLSConfig:      tlsCfg,
		Timeout:        kmCfg.Cosmian.Timeout,
		Provider:       "cosmian-kmip",
		DualReadWindow: kmCfg.DualReadWindow,
	}

	return crypto.NewCosmianKMIPManager(opts)
}

func buildCosmianTLSConfig(cfg config.CosmianConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
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

func main() {
	// Initialize logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	// Load configuration
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config.yaml"
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		logger.WithError(err).Fatal("Failed to load configuration")
	}

	// Set log level from config
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logger.WithError(err).Warn("Invalid log level, using info")
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)
	
	// Initialize debug logging based on log level
	debug.InitFromLogLevel(cfg.LogLevel)

	logger.WithFields(logrus.Fields{
		"version": version,
		"commit":  commit,
	}).Info("Starting S3 Encryption Gateway")

	// Initialize tracing if enabled
	var tracerProvider *sdktrace.TracerProvider
	if cfg.Tracing.Enabled {
		var err error
		tracerProvider, err = InitTracing(cfg.Tracing, logger)
		if err != nil {
			logger.WithError(err).Fatal("Failed to initialize tracing")
		}
		defer func() {
			if err := tracerProvider.Shutdown(context.Background()); err != nil {
				logger.WithError(err).Error("Failed to shutdown tracer provider")
			}
		}()
		logger.WithFields(logrus.Fields{
			"exporter":       cfg.Tracing.Exporter,
			"service_name":   cfg.Tracing.ServiceName,
			"sampling_ratio": cfg.Tracing.SamplingRatio,
		}).Info("Tracing initialized")
	}

	// Initialize metrics
	m := metrics.NewMetrics()
	metrics.SetVersion(version)

	// Start system metrics collector
	m.StartSystemMetricsCollector()

	// Initialize S3 client (only if useClientCredentials is not enabled)
	// When useClientCredentials is enabled, clients are created per-request from client credentials
	var s3Client s3.Client
	if !cfg.Backend.UseClientCredentials {
		s3Client, err = s3.NewClient(&cfg.Backend)
		if err != nil {
			logger.WithError(err).Fatal("Failed to create S3 client")
		}
		logger.Info("S3 backend client initialized with configured credentials")
	} else {
		logger.Info("Client credential passthrough enabled - S3 clients will be created per-request from client credentials")
	}

	// Load encryption password (required for both single password and KMS modes)
	var encryptionPassword string
	var keyManager crypto.KeyManager

	if cfg.Encryption.Password != "" {
		encryptionPassword = cfg.Encryption.Password
	} else if cfg.Encryption.KeyFile != "" {
		keyData, err := os.ReadFile(cfg.Encryption.KeyFile)
		if err != nil {
			logger.WithError(err).Fatal("Failed to read encryption key file")
		}
		encryptionPassword = string(keyData)
	}

	if encryptionPassword == "" {
		logger.Fatal("Encryption password is required (set ENCRYPTION_PASSWORD or encryption.password)")
	}

	activePassword := encryptionPassword
	if cfg.Encryption.KeyManager.Enabled {
		keyManager, err = buildKeyManager(cfg, logger)
		if err != nil {
			logger.WithError(err).Fatal("Failed to initialize key manager")
		}
		defer func() {
			if err := keyManager.Close(context.Background()); err != nil {
				logger.WithError(err).Warn("Failed to close key manager cleanly")
			}
		}()
		logger.WithFields(logrus.Fields{
			"provider": strings.ToLower(cfg.Encryption.KeyManager.Provider),
		}).Info("External key manager initialized")
	} else {
		logger.Info("Using single password mode (no key rotation)")
	}

	// Initialize compression engine if enabled
	var compressionEngine crypto.CompressionEngine
	if cfg.Compression.Enabled {
		compressionEngine = crypto.NewCompressionEngine(
			cfg.Compression.Enabled,
			cfg.Compression.MinSize,
			cfg.Compression.ContentTypes,
			cfg.Compression.Algorithm,
			cfg.Compression.Level,
		)
		logger.WithFields(logrus.Fields{
			"enabled":   cfg.Compression.Enabled,
			"algorithm": cfg.Compression.Algorithm,
			"min_size":  cfg.Compression.MinSize,
		}).Info("Compression enabled")
	}

	// Log hardware acceleration info
	hwInfo := crypto.GetHardwareAccelerationInfo()
	logger.WithFields(logrus.Fields{
		"aes_hardware_support": hwInfo["aes_hardware_support"],
		"architecture":         hwInfo["architecture"],
	}).Info("Hardware acceleration status")

	// Initialize encryption engine with compression, algorithm support, chunked mode, and key resolver (if KMS mode)
	var encryptionEngine crypto.EncryptionEngine

	// Default to chunked mode enabled unless explicitly disabled
	chunkedMode := cfg.Encryption.ChunkedMode
	if !cfg.Encryption.ChunkedMode && cfg.Encryption.ChunkSize == 0 {
		// If neither is set, default to enabled for new installations
		chunkedMode = true
	}

	chunkSize := cfg.Encryption.ChunkSize
	if chunkSize == 0 {
		chunkSize = crypto.DefaultChunkSize
	}

	encryptionEngine, err = crypto.NewEngineWithChunking(
		activePassword,
		compressionEngine,
		cfg.Encryption.PreferredAlgorithm,
		cfg.Encryption.SupportedAlgorithms,
		chunkedMode,
		chunkSize,
	)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create encryption engine")
	}
	if keyManager != nil {
		crypto.SetKeyManager(encryptionEngine, keyManager)
	}

	logger.WithFields(logrus.Fields{
		"preferred_algorithm":  cfg.Encryption.PreferredAlgorithm,
		"supported_algorithms": cfg.Encryption.SupportedAlgorithms,
		"chunked_mode":         chunkedMode,
		"chunk_size":           chunkSize,
	}).Info("Encryption configuration")

	// Initialize cache if enabled (Phase 5 feature)
	var objectCache cache.Cache
	if cfg.Cache.Enabled {
		objectCache = cache.NewMemoryCache(
			cfg.Cache.MaxSize,
			cfg.Cache.MaxItems,
			cfg.Cache.DefaultTTL,
		)
		logger.WithFields(logrus.Fields{
			"max_size":    cfg.Cache.MaxSize,
			"max_items":   cfg.Cache.MaxItems,
			"default_ttl": cfg.Cache.DefaultTTL,
		}).Info("Cache enabled")
	}

	// Initialize audit logger if enabled (Phase 5 feature)
	var auditLogger audit.Logger
	if cfg.Audit.Enabled {
		auditLogger = audit.NewLogger(cfg.Audit.MaxEvents, nil)
		logger.WithFields(logrus.Fields{
			"max_events": cfg.Audit.MaxEvents,
		}).Info("Audit logging enabled")
	}

	// Initialize API handler with Phase 5 features
	handler := api.NewHandlerWithFeatures(s3Client, encryptionEngine, logger, m, keyManager, objectCache, auditLogger, cfg)

	// Initialize configuration hot-reload (only if config file is specified)
	var configReloader *config.ConfigReloader
	var configApplier *ConfigChangeApplier

	if configPath != "" && configPath != "config.yaml" { // Only enable if explicit config file is provided
		// Create config change applier
		var rateLimiterPtr *middleware.RateLimiter
		if cfg.RateLimit.Enabled {
			rateLimiterPtr = middleware.NewRateLimiter(
				cfg.RateLimit.Limit,
				cfg.RateLimit.Window,
				logger,
			)
			defer rateLimiterPtr.Stop()
		}

		configApplier = NewConfigChangeApplier(logger, tracerProvider, rateLimiterPtr, objectCache, auditLogger, cfg)

		// Create and start config reloader
		var err error
		configReloader, err = config.NewConfigReloader(configPath, cfg, logger)
		if err != nil {
			logger.WithError(err).Fatal("Failed to initialize config reloader")
		}

		// Set the reload callback
		configReloader.SetOnReloadCallback(configApplier.ApplyConfigChanges)

		// Start config reloader in background
		go configReloader.Start()

		logger.WithField("config_file", configPath).Info("Configuration hot-reload enabled")
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
	httpHandler = middleware.SecurityHeadersMiddleware()(httpHandler)

	// Apply tracing middleware if tracing is enabled
	if cfg.Tracing.Enabled {
		httpHandler = middleware.TracingMiddleware(cfg.Tracing.RedactSensitive)(httpHandler)
	}

	// Apply bucket validation middleware if proxied bucket is configured
	if cfg.ProxiedBucket != "" {
		httpHandler = middleware.BucketValidationMiddleware(cfg.ProxiedBucket, logger)(httpHandler)
		logger.WithField("proxied_bucket", cfg.ProxiedBucket).Info("Single bucket proxy mode enabled")
	}

	// Add rate limiting if enabled
	if cfg.RateLimit.Enabled {
		// Use the rate limiter from config applier if hot-reload is enabled
		var rateLimiter *middleware.RateLimiter
		if configApplier != nil && configApplier.RateLimiter != nil {
			rateLimiter = configApplier.RateLimiter
		} else {
			rateLimiter = middleware.NewRateLimiter(
				cfg.RateLimit.Limit,
				cfg.RateLimit.Window,
				logger,
			)
			defer rateLimiter.Stop()
		}
		httpHandler = middleware.RateLimitMiddleware(rateLimiter)(httpHandler)
		logger.WithFields(logrus.Fields{
			"limit":  cfg.RateLimit.Limit,
			"window": cfg.RateLimit.Window,
		}).Info("Rate limiting enabled")
	}

	// Create HTTP server
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           httpHandler,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}

	// Start server in goroutine
	go func() {
		var err error
		if cfg.TLS.Enabled {
			logger.WithFields(logrus.Fields{
				"addr":      cfg.ListenAddr,
				"cert_file": cfg.TLS.CertFile,
				"key_file":  cfg.TLS.KeyFile,
			}).Info("Starting HTTPS server")
			err = server.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			logger.WithField("addr", cfg.ListenAddr).Info("Starting HTTP server")
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Failed to start server")
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Stop config reloader if enabled
	if configReloader != nil {
		configReloader.Stop()
		logger.Info("Configuration reloader stopped")
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
	} else {
		logger.Info("Server stopped gracefully")
	}
}
