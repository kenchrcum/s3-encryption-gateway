package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/kenneth/s3-encryption-gateway/internal/api"
	"github.com/kenneth/s3-encryption-gateway/internal/audit"
	"github.com/kenneth/s3-encryption-gateway/internal/cache"
	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/kenneth/s3-encryption-gateway/internal/metrics"
	"github.com/kenneth/s3-encryption-gateway/internal/middleware"
	"github.com/kenneth/s3-encryption-gateway/internal/s3"
	"github.com/sirupsen/logrus"
)

var (
	version = "dev"
	commit  = "unknown"
)

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

	logger.WithFields(logrus.Fields{
		"version": version,
		"commit":  commit,
	}).Info("Starting S3 Encryption Gateway")

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

	// Key Manager is optional - use it only if explicitly enabled via config
	// This maintains backward compatibility with single password mode
	var activePassword string
	if cfg.Encryption.KeyManager.Enabled {
		// Initialize key manager (Phase 5 feature - KMS mode)
		keyManager, err = crypto.NewKeyManager(encryptionPassword)
		if err != nil {
			logger.WithError(err).Fatal("Failed to create key manager")
		}

		// Get active key from key manager
		var keyVersion int
		activePassword, keyVersion, err = keyManager.GetActiveKey()
		if err != nil {
			logger.WithError(err).Fatal("Failed to get active key")
		}
		logger.WithFields(logrus.Fields{
			"key_version": keyVersion,
		}).Info("Key manager (KMS mode) initialized")
	} else {
		// Single password mode (backward compatible)
		activePassword = encryptionPassword
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
    
    if cfg.Encryption.KeyManager.Enabled {
        resolver := func(version int) (string, bool) {
            if keyManager == nil {
                return "", false
            }
            pass, err := keyManager.GetKeyVersion(version)
            if err != nil || pass == "" {
                return "", false
            }
            return pass, true
        }
        // Create engine with chunking, then set resolver
        encryptionEngine, err = crypto.NewEngineWithChunking(
            activePassword,
            compressionEngine,
            cfg.Encryption.PreferredAlgorithm,
            cfg.Encryption.SupportedAlgorithms,
            chunkedMode,
            chunkSize,
        )
        if err == nil {
            crypto.SetKeyResolver(encryptionEngine, resolver)
        }
    } else {
        encryptionEngine, err = crypto.NewEngineWithChunking(
            activePassword,
            compressionEngine,
            cfg.Encryption.PreferredAlgorithm,
            cfg.Encryption.SupportedAlgorithms,
            chunkedMode,
            chunkSize,
        )
    }
	if err != nil {
		logger.WithError(err).Fatal("Failed to create encryption engine")
	}

	logger.WithFields(logrus.Fields{
		"preferred_algorithm": cfg.Encryption.PreferredAlgorithm,
		"supported_algorithms": cfg.Encryption.SupportedAlgorithms,
		"chunked_mode": chunkedMode,
		"chunk_size": chunkSize,
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
			"max_size":     cfg.Cache.MaxSize,
			"max_items":    cfg.Cache.MaxItems,
			"default_ttl":  cfg.Cache.DefaultTTL,
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

	// Setup router
	router := mux.NewRouter()

	// Register metrics endpoint
	router.Handle("/metrics", m.Handler()).Methods("GET")

	// Register API routes
	handler.RegisterRoutes(router)

	// Apply middleware
	httpHandler := middleware.RecoveryMiddleware(logger)(router)
	httpHandler = middleware.LoggingMiddleware(logger)(httpHandler)
	httpHandler = middleware.SecurityHeadersMiddleware()(httpHandler)
	
	// Apply bucket validation middleware if proxied bucket is configured
	if cfg.ProxiedBucket != "" {
		httpHandler = middleware.BucketValidationMiddleware(cfg.ProxiedBucket, logger)(httpHandler)
		logger.WithField("proxied_bucket", cfg.ProxiedBucket).Info("Single bucket proxy mode enabled")
	}

	// Add rate limiting if enabled
	if cfg.RateLimit.Enabled {
		rateLimiter := middleware.NewRateLimiter(
			cfg.RateLimit.Limit,
			cfg.RateLimit.Window,
			logger,
		)
		defer rateLimiter.Stop()
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

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
	} else {
		logger.Info("Server stopped gracefully")
	}
}
