// Package admin provides the admin API server for the S3 encryption gateway.
//
// The admin server runs on a separate listener from the S3 data-plane,
// providing endpoints for key rotation management and (future) diagnostic
// endpoints. It is gated by bearer-token authentication with constant-time
// comparison.
package admin

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/sirupsen/logrus"
)

// contextKey is a private type for context keys in this package.
type contextKey int

const (
	// ctxKeyAdmin is set on requests arriving on the admin listener.
	ctxKeyAdmin contextKey = iota
)

// IsAdminRequest returns true if the request arrived on the admin listener.
// This is the reusable predicate consumed by V0.6-S3-2.
func IsAdminRequest(r *http.Request) bool {
	v, _ := r.Context().Value(ctxKeyAdmin).(bool)
	return v
}

// Server owns the admin HTTP listener and mux.
type Server struct {
	// mu guards httpServer and listener, which are written by Start and read
	// by Shutdown and BoundAddr. Without this mutex, calls to Shutdown that
	// race Start (e.g. a test cleanup fired while the admin goroutine is
	// still binding the listener) trip the race detector.
	mu         sync.Mutex
	httpServer *http.Server
	listener   net.Listener
	cfg        config.AdminConfig
	logger     *logrus.Logger
	mux        *http.ServeMux
}

// NewServer creates a new admin Server. The caller must call RegisterRoutes
// before Start to mount handlers on the admin mux.
func NewServer(cfg config.AdminConfig, logger *logrus.Logger) *Server {
	mux := http.NewServeMux()
	s := &Server{
		cfg:    cfg,
		logger: logger,
		mux:    mux,
	}
	return s
}

// Mux returns the underlying ServeMux so callers can register routes.
func (s *Server) Mux() *http.ServeMux {
	return s.mux
}

// Start begins listening on the admin address. It blocks until the context is
// cancelled or Shutdown is called.
func (s *Server) Start(ctx context.Context) error {
	// Build the handler chain: admin-context → bearer auth → rate limit → mux
	tokenSource := s.buildTokenSource()
	handler := http.Handler(s.mux)

	// Apply rate limiting
	if s.cfg.RateLimit.RequestsPerMinute > 0 {
		rl := NewRateLimiter(s.cfg.RateLimit.RequestsPerMinute, s.logger)
		handler = rl.Middleware(handler)
	}

	// Apply bearer authentication
	handler = BearerAuthMiddleware(tokenSource, s.logger)(handler)

	// Set admin context flag on every request
	handler = adminContextMiddleware(handler)

	httpServer := &http.Server{
		Handler:           handler,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	listener, err := net.Listen("tcp", s.cfg.Address)
	if err != nil {
		return fmt.Errorf("admin: failed to listen on %s: %w", s.cfg.Address, err)
	}

	boundAddr := listener.Addr().String()
	s.logger.WithFields(logrus.Fields{
		"address":        boundAddr,
		"tls":            s.cfg.TLS.Enabled,
		"auth":           "bearer",
		"rate_limit_rpm": s.cfg.RateLimit.RequestsPerMinute,
	}).Info("admin_api_enabled")

	if s.cfg.TLS.Enabled {
		tlsCert, certErr := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		if certErr != nil {
			listener.Close()
			return fmt.Errorf("admin: failed to load TLS certificate: %w", certErr)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		}
		listener = tls.NewListener(listener, tlsCfg)
	}

	// Publish the listener + httpServer atomically so Shutdown can observe
	// them. If Shutdown was called before we got here, s.httpServer will be
	// non-nil (we stash a sentinel below); close the listener and bail.
	s.mu.Lock()
	s.httpServer = httpServer
	s.listener = listener
	s.mu.Unlock()

	if err := httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("admin: serve error: %w", err)
	}
	return nil
}

// Shutdown gracefully shuts down the admin server. It is safe to call
// concurrently with Start: if Start has not yet published the http.Server,
// Shutdown returns nil and the subsequent Start will see the listener close
// and exit cleanly.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	hs := s.httpServer
	s.mu.Unlock()
	if hs == nil {
		return nil
	}
	return hs.Shutdown(ctx)
}

// BoundAddr returns the address the server is listening on.
// Returns empty string if not yet started.
func (s *Server) BoundAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// buildTokenSource returns a function that reads the bearer token. For
// token_file mode it re-reads the file on every call so that token rotation
// is supported at runtime.
func (s *Server) buildTokenSource() func() []byte {
	if s.cfg.Auth.TokenFile != "" {
		path := s.cfg.Auth.TokenFile
		return func() []byte {
			data, err := os.ReadFile(path)
			if err != nil {
				s.logger.WithError(err).Error("admin: failed to read token file")
				return nil
			}
			return []byte(strings.TrimSpace(string(data)))
		}
	}
	// Inline token (dev only)
	token := []byte(s.cfg.Auth.Token)
	return func() []byte {
		return token
	}
}

// adminContextMiddleware sets the admin context flag on every request.
func adminContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ctxKeyAdmin, true)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
