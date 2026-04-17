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

	s.httpServer = &http.Server{
		Handler:           handler,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	var err error
	s.listener, err = net.Listen("tcp", s.cfg.Address)
	if err != nil {
		return fmt.Errorf("admin: failed to listen on %s: %w", s.cfg.Address, err)
	}

	boundAddr := s.listener.Addr().String()
	s.logger.WithFields(logrus.Fields{
		"address":        boundAddr,
		"tls":            s.cfg.TLS.Enabled,
		"auth":           "bearer",
		"rate_limit_rpm": s.cfg.RateLimit.RequestsPerMinute,
	}).Info("admin_api_enabled")

	if s.cfg.TLS.Enabled {
		tlsCert, err := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		if err != nil {
			s.listener.Close()
			return fmt.Errorf("admin: failed to load TLS certificate: %w", err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		}
		s.listener = tls.NewListener(s.listener, tlsCfg)
	}

	if err := s.httpServer.Serve(s.listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("admin: serve error: %w", err)
	}
	return nil
}

// Shutdown gracefully shuts down the admin server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

// BoundAddr returns the address the server is listening on.
// Returns empty string if not yet started.
func (s *Server) BoundAddr() string {
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
