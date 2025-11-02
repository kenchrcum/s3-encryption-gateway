package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
)

// LoggingMiddleware wraps handlers with request logging.
func LoggingMiddleware(logger *logrus.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Get request body size from Content-Length header for PUT/POST requests
			var requestBytes int64
			if r.Method == "PUT" || r.Method == "POST" {
				if contentLength := r.Header.Get("Content-Length"); contentLength != "" {
					if size, err := strconv.ParseInt(contentLength, 10, 64); err == nil {
						requestBytes = size
					}
				}
			}

			// Wrap response writer to capture status code
			rw := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(rw, r)

			duration := time.Since(start)

			// For PUT/POST, log request bytes; for GET/HEAD, log response bytes
			bytesLogged := rw.bytesWritten
			if requestBytes > 0 {
				bytesLogged = requestBytes
			}

			logger.WithFields(logrus.Fields{
				"method":      r.Method,
				"path":        r.URL.Path,
				"query":       r.URL.RawQuery,
				"remote_addr": r.RemoteAddr,
				"user_agent":  r.UserAgent(),
				"status":      rw.statusCode,
				"duration_ms": duration.Milliseconds(),
				"bytes":       bytesLogged,
			}).Info("HTTP request")
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}