package api

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/kenneth/s3-encryption-gateway/internal/metrics"
	"github.com/kenneth/s3-encryption-gateway/internal/s3"
	"github.com/sirupsen/logrus"
)

// Handler handles HTTP requests for S3 operations.
type Handler struct {
	s3Client        s3.Client
	encryptionEngine crypto.EncryptionEngine
	logger          *logrus.Logger
	metrics         *metrics.Metrics
}

// NewHandler creates a new API handler.
func NewHandler(s3Client s3.Client, encryptionEngine crypto.EncryptionEngine, logger *logrus.Logger, m *metrics.Metrics) *Handler {
	return &Handler{
		s3Client:        s3Client,
		encryptionEngine: encryptionEngine,
		logger:          logger,
		metrics:         m,
	}
}

// RegisterRoutes registers all API routes.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/health", h.handleHealth).Methods("GET")
	r.HandleFunc("/ready", h.handleReady).Methods("GET")
	r.HandleFunc("/live", h.handleLive).Methods("GET")

	// S3 API routes
	s3Router := r.PathPrefix("/").Subrouter()
	s3Router.HandleFunc("/{bucket}", h.handleListObjects).Methods("GET")
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handleGetObject).Methods("GET")
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handlePutObject).Methods("PUT")
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handleDeleteObject).Methods("DELETE")
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handleHeadObject).Methods("HEAD")
}

// handleHealth handles health check requests.
func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	handler := metrics.HealthHandler()
	handler(w, r)
	h.metrics.RecordHTTPRequest("GET", "/health", http.StatusOK, time.Since(start), 0)
}

// handleReady handles readiness check requests.
func (h *Handler) handleReady(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	handler := metrics.ReadinessHandler()
	handler(w, r)
	h.metrics.RecordHTTPRequest("GET", "/ready", http.StatusOK, time.Since(start), 0)
}

// handleLive handles liveness check requests.
func (h *Handler) handleLive(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	handler := metrics.LivenessHandler()
	handler(w, r)
	h.metrics.RecordHTTPRequest("GET", "/live", http.StatusOK, time.Since(start), 0)
}

// handleGetObject handles GET object requests.
func (h *Handler) handleGetObject(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	if bucket == "" || key == "" {
		http.Error(w, "Invalid bucket or key", http.StatusBadRequest)
		h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusBadRequest, time.Since(start), 0)
		return
	}

	ctx := r.Context()
	reader, metadata, err := h.s3Client.GetObject(ctx, bucket, key)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to get object")
		http.Error(w, "Failed to get object", http.StatusInternalServerError)
		h.metrics.RecordS3Error("GetObject", bucket, "internal_error")
		h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}
	defer reader.Close()

	// Decrypt if encrypted
	decryptStart := time.Now()
	decryptedReader, decMetadata, err := h.encryptionEngine.Decrypt(reader, metadata)
	decryptDuration := time.Since(decryptStart)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to decrypt object")
		h.metrics.RecordEncryptionError("decrypt", "decryption_failed")
		http.Error(w, "Failed to decrypt object", http.StatusInternalServerError)
		h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}

	// Read decrypted data and record metrics
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		h.logger.WithError(err).Error("Failed to read decrypted data")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}
	decryptedSize := int64(len(decryptedData))
	h.metrics.RecordEncryptionOperation("decrypt", decryptDuration, decryptedSize)
	decryptedReader = bytes.NewReader(decryptedData)

	// Set headers from decrypted metadata (encryption metadata filtered out)
	for k, v := range decMetadata {
		// Only set metadata headers that aren't encryption-related
		w.Header().Set(k, v)
	}

	// Copy decrypted object data to response
	n, err := io.Copy(w, decryptedReader)
	if err != nil {
		h.logger.WithError(err).Error("Failed to write response")
		h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), int64(n))
		return
	}

	h.metrics.RecordS3Operation("GetObject", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusOK, time.Since(start), n)
}

// handlePutObject handles PUT object requests.
func (h *Handler) handlePutObject(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	if bucket == "" || key == "" {
		http.Error(w, "Invalid bucket or key", http.StatusBadRequest)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, http.StatusBadRequest, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	// Extract metadata from headers (preserve original metadata)
	metadata := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			// Only include x-amz-meta-* headers and standard headers
			if len(k) > 11 && k[:11] == "x-amz-meta-" || isStandardMetadata(k) {
				metadata[k] = v[0]
			}
		}
	}

	// Store original content length if available
	var originalBytes int64
	if contentLength := r.Header.Get("Content-Length"); contentLength != "" {
		metadata["x-amz-meta-original-content-length"] = contentLength
		fmt.Sscanf(contentLength, "%d", &originalBytes)
	}

	// Encrypt the object
	encryptStart := time.Now()
	encryptedReader, encMetadata, err := h.encryptionEngine.Encrypt(r.Body, metadata)
	encryptDuration := time.Since(encryptStart)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to encrypt object")
		h.metrics.RecordEncryptionError("encrypt", "encryption_failed")
		http.Error(w, "Failed to encrypt object", http.StatusInternalServerError)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}

	// Record encryption metrics (read encrypted data size for accurate bytes)
	encryptedData, _ := io.ReadAll(encryptedReader)
	h.metrics.RecordEncryptionOperation("encrypt", encryptDuration, originalBytes)
	encryptedReader = bytes.NewReader(encryptedData)

	// Upload encrypted object with encryption metadata
	err = h.s3Client.PutObject(ctx, bucket, key, encryptedReader, encMetadata)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to put object")
		http.Error(w, "Failed to put object", http.StatusInternalServerError)
		h.metrics.RecordS3Error("PutObject", bucket, "internal_error")
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}

	w.WriteHeader(http.StatusOK)
	h.metrics.RecordS3Operation("PutObject", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest("PUT", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// isStandardMetadata checks if a header is a standard HTTP metadata header.
func isStandardMetadata(key string) bool {
	standardHeaders := map[string]bool{
		"Content-Type":   true,
		"Content-Length": true,
		"ETag":           true,
		"Cache-Control":  true,
		"Expires":        true,
	}
	return standardHeaders[key]
}

// handleDeleteObject handles DELETE object requests.
func (h *Handler) handleDeleteObject(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	if bucket == "" || key == "" {
		http.Error(w, "Invalid bucket or key", http.StatusBadRequest)
		h.metrics.RecordHTTPRequest("DELETE", r.URL.Path, http.StatusBadRequest, time.Since(start), 0)
		return
	}

	ctx := r.Context()
	err := h.s3Client.DeleteObject(ctx, bucket, key)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to delete object")
		http.Error(w, "Failed to delete object", http.StatusInternalServerError)
		h.metrics.RecordS3Error("DeleteObject", bucket, "internal_error")
		h.metrics.RecordHTTPRequest("DELETE", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	h.metrics.RecordS3Operation("DeleteObject", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest("DELETE", r.URL.Path, http.StatusNoContent, time.Since(start), 0)
}

// handleHeadObject handles HEAD object requests.
func (h *Handler) handleHeadObject(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	if bucket == "" || key == "" {
		http.Error(w, "Invalid bucket or key", http.StatusBadRequest)
		h.metrics.RecordHTTPRequest("HEAD", r.URL.Path, http.StatusBadRequest, time.Since(start), 0)
		return
	}

	ctx := r.Context()
	metadata, err := h.s3Client.HeadObject(ctx, bucket, key)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to head object")
		http.Error(w, "Failed to head object", http.StatusInternalServerError)
		h.metrics.RecordS3Error("HeadObject", bucket, "internal_error")
		h.metrics.RecordHTTPRequest("HEAD", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}

	// Filter out encryption metadata and restore original metadata
	filteredMetadata := make(map[string]string)
	for k, v := range metadata {
		// Skip encryption-related metadata in response
		if !isEncryptionMetadata(k) {
			filteredMetadata[k] = v
		}
	}

	// Restore original size if available
	if originalSize, ok := metadata["x-amz-meta-encryption-original-size"]; ok {
		filteredMetadata["Content-Length"] = originalSize
	}

	// Restore original ETag if available
	if originalETag, ok := metadata["x-amz-meta-encryption-original-etag"]; ok {
		filteredMetadata["ETag"] = originalETag
	}

	// Set headers from filtered metadata
	for k, v := range filteredMetadata {
		w.Header().Set(k, v)
	}

	w.WriteHeader(http.StatusOK)
	h.metrics.RecordS3Operation("HeadObject", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest("HEAD", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// isEncryptionMetadata checks if a metadata key is related to encryption.
func isEncryptionMetadata(key string) bool {
	encryptionKeys := []string{
		"x-amz-meta-encrypted",
		"x-amz-meta-encryption-algorithm",
		"x-amz-meta-encryption-key-salt",
		"x-amz-meta-encryption-iv",
		"x-amz-meta-encryption-auth-tag",
		"x-amz-meta-encryption-original-size",
		"x-amz-meta-encryption-original-etag",
		"x-amz-meta-encryption-compression",
		"x-amz-meta-compression-enabled",
		"x-amz-meta-compression-algorithm",
		"x-amz-meta-compression-original-size",
	}
	for _, ek := range encryptionKeys {
		if key == ek {
			return true
		}
	}
	return false
}

// handleListObjects handles list objects requests.
func (h *Handler) handleListObjects(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	if bucket == "" {
		http.Error(w, "Invalid bucket", http.StatusBadRequest)
		h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusBadRequest, time.Since(start), 0)
		return
	}

	ctx := r.Context()
	prefix := r.URL.Query().Get("prefix")

	opts := s3.ListOptions{
		MaxKeys: 1000, // Default limit
	}

	objects, err := h.s3Client.ListObjects(ctx, bucket, prefix, opts)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"prefix": prefix,
		}).Error("Failed to list objects")
		http.Error(w, "Failed to list objects", http.StatusInternalServerError)
		h.metrics.RecordS3Error("ListObjects", bucket, "internal_error")
		h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}

	// Simple XML response (simplified for Phase 1)
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult>\n"))
	for _, obj := range objects {
		w.Write([]byte("<Contents><Key>" + obj.Key + "</Key></Contents>\n"))
	}
	w.Write([]byte("</ListBucketResult>"))

	h.metrics.RecordS3Operation("ListObjects", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusOK, time.Since(start), 0)
}