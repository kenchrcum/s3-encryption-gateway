package api

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/kenneth/s3-encryption-gateway/internal/audit"
	"github.com/kenneth/s3-encryption-gateway/internal/cache"
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
	keyManager      crypto.KeyManager
	cache           cache.Cache
	auditLogger     audit.Logger
}

// NewHandler creates a new API handler (backward compatibility).
func NewHandler(s3Client s3.Client, encryptionEngine crypto.EncryptionEngine, logger *logrus.Logger, m *metrics.Metrics) *Handler {
	return NewHandlerWithFeatures(s3Client, encryptionEngine, logger, m, nil, nil, nil)
}

// NewHandlerWithFeatures creates a new API handler with Phase 5 features.
func NewHandlerWithFeatures(
	s3Client s3.Client,
	encryptionEngine crypto.EncryptionEngine,
	logger *logrus.Logger,
	m *metrics.Metrics,
	keyManager crypto.KeyManager,
	cache cache.Cache,
	auditLogger audit.Logger,
) *Handler {
	return &Handler{
		s3Client:        s3Client,
		encryptionEngine: encryptionEngine,
		logger:          logger,
		metrics:         m,
		keyManager:     keyManager,
		cache:          cache,
		auditLogger:    auditLogger,
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
	
	// Multipart upload routes
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handleCreateMultipartUpload).Methods("POST").Queries("uploads", "")
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handleUploadPart).Methods("PUT").Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId}")
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handleCompleteMultipartUpload).Methods("POST").Queries("uploadId", "{uploadId}")
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handleAbortMultipartUpload).Methods("DELETE").Queries("uploadId", "{uploadId}")
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handleListParts).Methods("GET").Queries("uploadId", "{uploadId}")
	
	// Batch operations
	s3Router.HandleFunc("/{bucket}", h.handleDeleteObjects).Methods("POST").Queries("delete", "")
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
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()
	
	// Extract version ID if provided
	var versionID *string
	if vid := r.URL.Query().Get("versionId"); vid != "" {
		versionID = &vid
	}

    // Get range header if present
    var rangeHeader *string
    if rg := r.Header.Get("Range"); rg != "" {
        rangeHeader = &rg
    }

	// Check cache first if enabled and no range request
	if h.cache != nil && rangeHeader == nil && versionID == nil {
		if cachedEntry, ok := h.cache.Get(ctx, bucket, key); ok {
			// Serve from cache
			for k, v := range cachedEntry.Metadata {
				w.Header().Set(k, v)
			}
			w.WriteHeader(http.StatusOK)
			w.Write(cachedEntry.Data)
			h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusOK, time.Since(start), int64(len(cachedEntry.Data)))
			if h.auditLogger != nil {
				h.auditLogger.LogAccess("get", bucket, key, getClientIP(r), r.UserAgent(), getRequestID(r), true, nil, time.Since(start))
			}
			return
		}
	}

    // If Range is requested, avoid requesting a ranged ciphertext when object is encrypted.
    // Determine encryption via HEAD first to decide whether to forward Range to backend.
    backendRange := rangeHeader
    if rangeHeader != nil {
        headMeta, headErr := h.s3Client.HeadObject(ctx, bucket, key, versionID)
        if headErr == nil && h.encryptionEngine.IsEncrypted(headMeta) {
            backendRange = nil
        }
        // On HEAD error, fall back to forwarding Range (best effort)
    }

    reader, metadata, err := h.s3Client.GetObject(ctx, bucket, key, versionID, backendRange)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to get object")
		h.metrics.RecordS3Error("GetObject", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest("GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
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
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to decrypt object",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Read decrypted data and record metrics
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		h.logger.WithError(err).Error("Failed to read decrypted data")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to read decrypted data",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		if h.auditLogger != nil {
			alg := metadata[crypto.MetaAlgorithm]
			if alg == "" {
				alg = crypto.AlgorithmAES256GCM
			}
			h.auditLogger.LogDecrypt(bucket, key, alg, 0, false, err, decryptDuration, nil)
		}
		return
	}
	decryptedSize := int64(len(decryptedData))
	h.metrics.RecordEncryptionOperation("decrypt", decryptDuration, decryptedSize)

	// Get algorithm and key version from metadata for audit logging
	algorithm := metadata[crypto.MetaAlgorithm]
	if algorithm == "" {
		algorithm = crypto.AlgorithmAES256GCM
	}
	keyVersion := 0 // Default if not available
	if h.keyManager != nil {
		_, keyVersion, _ = h.keyManager.GetActiveKey()
	}

	// Audit logging
	if h.auditLogger != nil {
		h.auditLogger.LogDecrypt(bucket, key, algorithm, keyVersion, true, nil, decryptDuration, nil)
	}

	// Store in cache if enabled and no range/version request
	if h.cache != nil && rangeHeader == nil && versionID == nil {
		if err := h.cache.Set(ctx, bucket, key, decryptedData, decMetadata, 0); err != nil {
			h.logger.WithError(err).WithFields(logrus.Fields{
				"bucket": bucket,
				"key":    key,
			}).Warn("Failed to cache object")
		}
	}

    // Apply range request if present (after decryption) and set headers BEFORE WriteHeader
    outputData := decryptedData
    if rangeHeader != nil && *rangeHeader != "" {
        outputData, err = applyRangeRequest(decryptedData, *rangeHeader)
        if err != nil {
            s3Err := &S3Error{
                Code:       "InvalidRange",
                Message:    fmt.Sprintf("Invalid range request: %v", err),
                Resource:   r.URL.Path,
                HTTPStatus: http.StatusRequestedRangeNotSatisfiable,
            }
            s3Err.WriteXML(w)
            h.metrics.RecordHTTPRequest("GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
            return
        }
        // Set decrypted metadata headers
        for k, v := range decMetadata {
            if !isEncryptionMetadata(k) {
                w.Header().Set(k, v)
            }
        }
        if versionID != nil && *versionID != "" {
            w.Header().Set("x-amz-version-id", *versionID)
        }
        w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", 0, len(outputData)-1, len(decryptedData)))
        w.Header().Set("Content-Length", fmt.Sprintf("%d", len(outputData)))
        w.WriteHeader(http.StatusPartialContent)
    } else {
        // Set decrypted metadata headers
        for k, v := range decMetadata {
            if !isEncryptionMetadata(k) {
                w.Header().Set(k, v)
            }
        }
        if versionID != nil && *versionID != "" {
            w.Header().Set("x-amz-version-id", *versionID)
        }
        w.Header().Set("Content-Length", fmt.Sprintf("%d", len(outputData)))
        w.WriteHeader(http.StatusOK)
    }

	// Copy decrypted object data to response
	n, err := w.Write(outputData)
	if err != nil {
		h.logger.WithError(err).Error("Failed to write response")
		h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), int64(n))
		return
	}

	h.metrics.RecordS3Operation("GetObject", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusOK, time.Since(start), int64(n))
}

// handlePutObject handles PUT object requests.
func (h *Handler) handlePutObject(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	if bucket == "" || key == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	// Check if this is a copy operation
	copySource := r.Header.Get("x-amz-copy-source")
	if copySource != "" {
		// Handle copy operation
		h.handleCopyObject(w, r, bucket, key, copySource, start)
		return
	}

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
	
	// Get algorithm and key version for audit logging
	algorithm := encMetadata[crypto.MetaAlgorithm]
	if algorithm == "" {
		algorithm = crypto.AlgorithmAES256GCM
	}
	keyVersion := 0
	if h.keyManager != nil {
		_, keyVersion, _ = h.keyManager.GetActiveKey()
	}

	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to encrypt object")
		h.metrics.RecordEncryptionError("encrypt", "encryption_failed")
		
		// Audit logging for failed encryption
		if h.auditLogger != nil {
			h.auditLogger.LogEncrypt(bucket, key, algorithm, keyVersion, false, err, encryptDuration, nil)
		}
		
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to encrypt object",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Audit logging for successful encryption
	if h.auditLogger != nil {
		h.auditLogger.LogEncrypt(bucket, key, algorithm, keyVersion, true, nil, encryptDuration, nil)
	}

	// Invalidate cache for this object if cache is enabled
	if h.cache != nil {
		h.cache.Delete(ctx, bucket, key)
	}

	// Record encryption metrics (read encrypted data size for accurate bytes)
	encryptedData, _ := io.ReadAll(encryptedReader)
	h.metrics.RecordEncryptionOperation("encrypt", encryptDuration, originalBytes)
	encryptedReader = bytes.NewReader(encryptedData)

	// Upload encrypted object with encryption metadata
	err = h.s3Client.PutObject(ctx, bucket, key, encryptedReader, encMetadata)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to put object")
		h.metrics.RecordS3Error("PutObject", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
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
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("DELETE", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()
	
	// Extract version ID if provided
	var versionID *string
	if vid := r.URL.Query().Get("versionId"); vid != "" {
		versionID = &vid
	}

	err := h.s3Client.DeleteObject(ctx, bucket, key, versionID)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to delete object")
		h.metrics.RecordS3Error("DeleteObject", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest("DELETE", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		if h.auditLogger != nil {
			h.auditLogger.LogAccess("delete", bucket, key, getClientIP(r), r.UserAgent(), getRequestID(r), false, err, time.Since(start))
		}
		return
	}

	// Invalidate cache for deleted object
	if h.cache != nil {
		h.cache.Delete(ctx, bucket, key)
	}

	// Audit logging
	if h.auditLogger != nil {
		h.auditLogger.LogAccess("delete", bucket, key, getClientIP(r), r.UserAgent(), getRequestID(r), true, nil, time.Since(start))
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
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("HEAD", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()
	
	// Extract version ID if provided
	var versionID *string
	if vid := r.URL.Query().Get("versionId"); vid != "" {
		versionID = &vid
	}

	metadata, err := h.s3Client.HeadObject(ctx, bucket, key, versionID)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to head object")
		h.metrics.RecordS3Error("HeadObject", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest("HEAD", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
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
	} else if originalSize, ok := metadata["x-amz-meta-original-content-length"]; ok {
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
	
	// Preserve version ID in response if present
	if versionID != nil && *versionID != "" {
		w.Header().Set("x-amz-version-id", *versionID)
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
		s3Err := ErrInvalidBucketName
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()
	prefix := r.URL.Query().Get("prefix")
	delimiter := r.URL.Query().Get("delimiter")
	marker := r.URL.Query().Get("marker")
	maxKeys := int32(1000) // Default
	if mk := r.URL.Query().Get("max-keys"); mk != "" {
		fmt.Sscanf(mk, "%d", &maxKeys)
	}

	opts := s3.ListOptions{
		Delimiter: delimiter,
		Marker:    marker,
		MaxKeys:   maxKeys,
	}

	objects, err := h.s3Client.ListObjects(ctx, bucket, prefix, opts)
	if err != nil {
		s3Err := TranslateError(err, bucket, "")
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"prefix": prefix,
		}).Error("Failed to list objects")
		h.metrics.RecordS3Error("ListObjects", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest("GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Generate proper S3 ListBucketResult XML response
	xmlResponse := generateListObjectsXML(bucket, prefix, delimiter, objects)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xmlResponse))

	h.metrics.RecordS3Operation("ListObjects", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusOK, time.Since(start), int64(len(xmlResponse)))
}

// applyRangeRequest applies a Range header request to data.
func applyRangeRequest(data []byte, rangeHeader string) ([]byte, error) {
	// Parse Range header: "bytes=start-end" or "bytes=start-" or "bytes=-suffix"
	if len(rangeHeader) < 6 || rangeHeader[:6] != "bytes=" {
		return nil, fmt.Errorf("invalid range header format")
	}

	rangeSpec := rangeHeader[6:]
	dataLen := int64(len(data))

	var start, end int64
	if rangeSpec[0] == '-' {
		// Suffix range: "-suffix" means last N bytes
		var suffix int64
		if _, err := fmt.Sscanf(rangeSpec, "-%d", &suffix); err != nil {
			return nil, fmt.Errorf("invalid suffix range: %w", err)
		}
		start = dataLen - suffix
		if start < 0 {
			start = 0
		}
		end = dataLen - 1
	} else {
		// Range: "start-end" or "start-"
		if strings.Contains(rangeSpec, "-") {
			parts := strings.Split(rangeSpec, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid range format")
			}
			if _, err := fmt.Sscanf(parts[0], "%d", &start); err != nil {
				return nil, fmt.Errorf("invalid start: %w", err)
			}
			if parts[1] == "" {
				end = dataLen - 1
			} else {
				if _, err := fmt.Sscanf(parts[1], "%d", &end); err != nil {
					return nil, fmt.Errorf("invalid end: %w", err)
				}
			}
		} else {
			return nil, fmt.Errorf("invalid range format")
		}
	}

	// Validate range
	if start < 0 || start >= dataLen || end < start || end >= dataLen {
		return nil, fmt.Errorf("range not satisfiable: %d-%d (size: %d)", start, end, dataLen)
	}

	return data[start : end+1], nil
}

// generateListObjectsXML generates S3-compatible ListBucketResult XML.
func generateListObjectsXML(bucket, prefix, delimiter string, objects []s3.ObjectInfo) string {
	var xml strings.Builder
	xml.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	xml.WriteString("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" + "\n")
	xml.WriteString(fmt.Sprintf("  <Name>%s</Name>\n", bucket))
	if prefix != "" {
		xml.WriteString(fmt.Sprintf("  <Prefix>%s</Prefix>\n", prefix))
	}
	if delimiter != "" {
		xml.WriteString(fmt.Sprintf("  <Delimiter>%s</Delimiter>\n", delimiter))
	}
	xml.WriteString(fmt.Sprintf("  <MaxKeys>%d</MaxKeys>\n", len(objects)))
	xml.WriteString(fmt.Sprintf("  <IsTruncated>false</IsTruncated>\n"))

	for _, obj := range objects {
		xml.WriteString("  <Contents>\n")
		xml.WriteString(fmt.Sprintf("    <Key>%s</Key>\n", obj.Key))
		xml.WriteString(fmt.Sprintf("    <LastModified>%s</LastModified>\n", obj.LastModified))
		xml.WriteString(fmt.Sprintf("    <ETag>%s</ETag>\n", obj.ETag))
		xml.WriteString(fmt.Sprintf("    <Size>%d</Size>\n", obj.Size))
		xml.WriteString("    <StorageClass>STANDARD</StorageClass>\n")
		xml.WriteString("  </Contents>\n")
	}
	xml.WriteString("</ListBucketResult>")
	return xml.String()
}

// handleCreateMultipartUpload handles multipart upload initiation.
func (h *Handler) handleCreateMultipartUpload(w http.ResponseWriter, r *http.Request) {
    // Temporary: multipart uploads are not supported yet with encryption
    s3Err := &S3Error{
        Code:       "NotImplemented",
        Message:    "Multipart uploads are not supported",
        Resource:   r.URL.Path,
        HTTPStatus: http.StatusNotImplemented,
    }
    s3Err.WriteXML(w)
    return
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	if bucket == "" || key == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	// Extract metadata from headers
	metadata := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			if len(k) > 11 && k[:11] == "x-amz-meta-" || isStandardMetadata(k) {
				metadata[k] = v[0]
			}
		}
	}

	uploadID, err := h.s3Client.CreateMultipartUpload(ctx, bucket, key, metadata)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to create multipart upload")
		h.metrics.RecordS3Error("CreateMultipartUpload", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest("POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Return XML response with upload ID
	type InitiateMultipartUploadResult struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		UploadId string   `xml:"UploadId"`
	}

	result := InitiateMultipartUploadResult{
		Bucket:   bucket,
		Key:      key,
		UploadId: uploadID,
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(result)

	h.metrics.RecordS3Operation("CreateMultipartUpload", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest("POST", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// handleUploadPart handles uploading a part in a multipart upload.
func (h *Handler) handleUploadPart(w http.ResponseWriter, r *http.Request) {
    s3Err := &S3Error{
        Code:       "NotImplemented",
        Message:    "Multipart uploads are not supported",
        Resource:   r.URL.Path,
        HTTPStatus: http.StatusNotImplemented,
    }
    s3Err.WriteXML(w)
    return
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]
	uploadID := vars["uploadId"]
	partNumberStr := vars["partNumber"]

	if bucket == "" || key == "" || uploadID == "" || partNumberStr == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	partNumber, err := strconv.ParseInt(partNumberStr, 10, 32)
	if err != nil || partNumber < 1 {
		s3Err := &S3Error{
			Code:       "InvalidArgument",
			Message:    "Invalid part number",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	// Encrypt the part data
	metadata := make(map[string]string)
	encryptedReader, _, err := h.encryptionEngine.Encrypt(r.Body, metadata)
	if err != nil {
		h.logger.WithError(err).Error("Failed to encrypt part")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to encrypt part",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	etag, err := h.s3Client.UploadPart(ctx, bucket, key, uploadID, int32(partNumber), encryptedReader)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":    bucket,
			"key":       key,
			"uploadID":  uploadID,
			"partNumber": partNumber,
		}).Error("Failed to upload part")
		h.metrics.RecordS3Error("UploadPart", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
	h.metrics.RecordS3Operation("UploadPart", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest("PUT", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// handleCompleteMultipartUpload handles completing a multipart upload.
func (h *Handler) handleCompleteMultipartUpload(w http.ResponseWriter, r *http.Request) {
    s3Err := &S3Error{
        Code:       "NotImplemented",
        Message:    "Multipart uploads are not supported",
        Resource:   r.URL.Path,
        HTTPStatus: http.StatusNotImplemented,
    }
    s3Err.WriteXML(w)
    return
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]
	uploadID := vars["uploadId"]

	if bucket == "" || key == "" || uploadID == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	// Parse multipart upload completion XML
	type CompleteMultipartUpload struct {
		XMLName xml.Name `xml:"CompleteMultipartUpload"`
		Parts   []struct {
			XMLName    xml.Name `xml:"Part"`
			PartNumber int32    `xml:"PartNumber"`
			ETag       string   `xml:"ETag"`
		} `xml:"Part"`
	}

	var completeReq CompleteMultipartUpload
	if err := xml.NewDecoder(r.Body).Decode(&completeReq); err != nil {
		s3Err := &S3Error{
			Code:       "MalformedXML",
			Message:    "The XML you provided was not well-formed or did not validate against our published schema",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Convert to CompletedPart slice
	parts := make([]s3.CompletedPart, len(completeReq.Parts))
	for i, p := range completeReq.Parts {
		parts[i] = s3.CompletedPart{
			PartNumber: p.PartNumber,
			ETag:       p.ETag,
		}
	}

	etag, err := h.s3Client.CompleteMultipartUpload(ctx, bucket, key, uploadID, parts)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploadID": uploadID,
		}).Error("Failed to complete multipart upload")
		h.metrics.RecordS3Error("CompleteMultipartUpload", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest("POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Return XML response
	type CompleteMultipartUploadResult struct {
		XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
		Location string   `xml:"Location"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		ETag     string   `xml:"ETag"`
	}

	result := CompleteMultipartUploadResult{
		Location: fmt.Sprintf("/%s/%s", bucket, key),
		Bucket:   bucket,
		Key:      key,
		ETag:     etag,
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(result)

	h.metrics.RecordS3Operation("CompleteMultipartUpload", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest("POST", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// handleAbortMultipartUpload handles aborting a multipart upload.
func (h *Handler) handleAbortMultipartUpload(w http.ResponseWriter, r *http.Request) {
    s3Err := &S3Error{
        Code:       "NotImplemented",
        Message:    "Multipart uploads are not supported",
        Resource:   r.URL.Path,
        HTTPStatus: http.StatusNotImplemented,
    }
    s3Err.WriteXML(w)
    return
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]
	uploadID := vars["uploadId"]

	if bucket == "" || key == "" || uploadID == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("DELETE", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	err := h.s3Client.AbortMultipartUpload(ctx, bucket, key, uploadID)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploadID": uploadID,
		}).Error("Failed to abort multipart upload")
		h.metrics.RecordS3Error("AbortMultipartUpload", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest("DELETE", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	h.metrics.RecordS3Operation("AbortMultipartUpload", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest("DELETE", r.URL.Path, http.StatusNoContent, time.Since(start), 0)
}

// handleListParts handles listing parts of a multipart upload.
func (h *Handler) handleListParts(w http.ResponseWriter, r *http.Request) {
    s3Err := &S3Error{
        Code:       "NotImplemented",
        Message:    "Multipart uploads are not supported",
        Resource:   r.URL.Path,
        HTTPStatus: http.StatusNotImplemented,
    }
    s3Err.WriteXML(w)
    return
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]
	uploadID := vars["uploadId"]

	if bucket == "" || key == "" || uploadID == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	parts, err := h.s3Client.ListParts(ctx, bucket, key, uploadID)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploadID": uploadID,
		}).Error("Failed to list parts")
		h.metrics.RecordS3Error("ListParts", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest("GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Generate XML response
	type ListPartsResult struct {
		XMLName xml.Name `xml:"ListPartsResult"`
			Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		UploadId string   `xml:"UploadId"`
		Parts    []struct {
			PartNumber   int32  `xml:"PartNumber"`
			ETag         string `xml:"ETag"`
			Size         int64  `xml:"Size"`
			LastModified string `xml:"LastModified"`
		} `xml:"Part"`
	}

	result := ListPartsResult{
		Bucket:   bucket,
		Key:      key,
		UploadId: uploadID,
		Parts:    make([]struct {
			PartNumber   int32  `xml:"PartNumber"`
			ETag         string `xml:"ETag"`
			Size         int64  `xml:"Size"`
			LastModified string `xml:"LastModified"`
		}, len(parts)),
	}

	for i, p := range parts {
		result.Parts[i].PartNumber = p.PartNumber
		result.Parts[i].ETag = p.ETag
		result.Parts[i].Size = p.Size
		result.Parts[i].LastModified = p.LastModified
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(result)

	h.metrics.RecordS3Operation("ListParts", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// handleCopyObject handles PUT Object Copy requests.
func (h *Handler) handleCopyObject(w http.ResponseWriter, r *http.Request, dstBucket, dstKey, copySource string, start time.Time) {
	// Parse copy source: format is "bucket/key" or "bucket/key?versionId=xxx"
	parts := strings.SplitN(copySource, "/", 2)
	if len(parts) != 2 {
		s3Err := &S3Error{
			Code:       "InvalidArgument",
			Message:    "Invalid x-amz-copy-source header",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	srcBucket := parts[0]
	srcKeyAndVersion := parts[1]
	
	// Parse version ID if present
	var srcVersionID *string
	if strings.Contains(srcKeyAndVersion, "?versionId=") {
		keyParts := strings.SplitN(srcKeyAndVersion, "?versionId=", 2)
		srcKeyAndVersion = keyParts[0]
		if len(keyParts) > 1 {
			srcVersionID = &keyParts[1]
		}
	}
	srcKey := strings.TrimPrefix(srcKeyAndVersion, "/")

	ctx := r.Context()

	// Get source object (decrypt if encrypted)
	srcReader, srcMetadata, err := h.s3Client.GetObject(ctx, srcBucket, srcKey, srcVersionID, nil)
	if err != nil {
		s3Err := TranslateError(err, srcBucket, srcKey)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"srcBucket": srcBucket,
			"srcKey":    srcKey,
			"dstBucket": dstBucket,
			"dstKey":    dstKey,
		}).Error("Failed to get source object for copy")
		h.metrics.RecordS3Error("CopyObject", dstBucket, s3Err.Code)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}
	defer srcReader.Close()

	// Decrypt source if encrypted
	decryptedReader, _, err := h.encryptionEngine.Decrypt(srcReader, srcMetadata)
	if err != nil {
		h.logger.WithError(err).Error("Failed to decrypt source object for copy")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to decrypt source object",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Read decrypted data
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		h.logger.WithError(err).Error("Failed to read decrypted source object")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to read source object",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Extract destination metadata from headers
	dstMetadata := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			if len(k) > 11 && k[:11] == "x-amz-meta-" || isStandardMetadata(k) {
				dstMetadata[k] = v[0]
			}
		}
	}

	// Re-encrypt for destination
	encryptedReader, encMetadata, err := h.encryptionEngine.Encrypt(bytes.NewReader(decryptedData), dstMetadata)
	if err != nil {
		h.logger.WithError(err).Error("Failed to encrypt destination object")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to encrypt destination object",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Read encrypted data
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		h.logger.WithError(err).Error("Failed to read encrypted destination object")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to read encrypted destination object",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

    // Upload encrypted copy
    err = h.s3Client.PutObject(ctx, dstBucket, dstKey, bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		s3Err := TranslateError(err, dstBucket, dstKey)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"srcBucket": srcBucket,
			"srcKey":    srcKey,
			"dstBucket": dstBucket,
			"dstKey":    dstKey,
		}).Error("Failed to put copied object")
		h.metrics.RecordS3Error("CopyObject", dstBucket, s3Err.Code)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

    // Fetch ETag via HEAD to return accurate ETag
    headMeta, _ := h.s3Client.HeadObject(ctx, dstBucket, dstKey, nil)
    etag := headMeta["ETag"]

    // Return CopyObjectResult XML
	type CopyObjectResult struct {
		XMLName      xml.Name `xml:"CopyObjectResult"`
		ETag         string   `xml:"ETag"`
		LastModified string   `xml:"LastModified"`
	}

	result := CopyObjectResult{
        ETag:         etag,
		LastModified: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(result)

	h.metrics.RecordS3Operation("CopyObject", dstBucket, time.Since(start))
	h.metrics.RecordHTTPRequest("PUT", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// handleDeleteObjects handles batch delete requests.
func (h *Handler) handleDeleteObjects(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	if bucket == "" {
		s3Err := ErrInvalidBucketName
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	// Parse Delete request XML
	type DeleteRequest struct {
		XMLName xml.Name `xml:"Delete"`
		Objects []struct {
			XMLName   xml.Name `xml:"Object"`
			Key       string   `xml:"Key"`
			VersionID string   `xml:"VersionId,omitempty"`
		} `xml:"Object"`
		Quiet bool `xml:"Quiet,omitempty"`
	}

	var deleteReq DeleteRequest
	if err := xml.NewDecoder(r.Body).Decode(&deleteReq); err != nil {
		s3Err := &S3Error{
			Code:       "MalformedXML",
			Message:    "The XML you provided was not well-formed or did not validate against our published schema",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Convert to ObjectIdentifier slice
	identifiers := make([]s3.ObjectIdentifier, len(deleteReq.Objects))
	for i, obj := range deleteReq.Objects {
		identifiers[i] = s3.ObjectIdentifier{
			Key:       obj.Key,
			VersionID: obj.VersionID,
		}
	}

	deleted, errors, err := h.s3Client.DeleteObjects(ctx, bucket, identifiers)
	if err != nil {
		s3Err := TranslateError(err, bucket, "")
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
		}).Error("Failed to delete objects")
		h.metrics.RecordS3Error("DeleteObjects", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest("POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Invalidate cache for deleted objects
	if h.cache != nil {
		for _, del := range deleted {
			h.cache.Delete(ctx, bucket, del.Key)
		}
	}

	// Audit logging for batch delete
	if h.auditLogger != nil {
		for _, del := range deleted {
			h.auditLogger.LogAccess("delete", bucket, del.Key, getClientIP(r), r.UserAgent(), getRequestID(r), true, nil, time.Since(start))
		}
		for _, errObj := range errors {
			h.auditLogger.LogAccess("delete", bucket, errObj.Key, getClientIP(r), r.UserAgent(), getRequestID(r), false, fmt.Errorf("%s: %s", errObj.Code, errObj.Message), time.Since(start))
		}
	}

	// Generate response XML
	type DeleteResult struct {
		XMLName xml.Name `xml:"DeleteResult"`
		Deleted []struct {
			XMLName      xml.Name `xml:"Deleted"`
			Key          string   `xml:"Key"`
			VersionID    string   `xml:"VersionId,omitempty"`
			DeleteMarker bool     `xml:"DeleteMarker,omitempty"`
		} `xml:"Deleted"`
		Errors []struct {
			XMLName xml.Name `xml:"Error"`
			Key     string   `xml:"Key"`
			Code    string   `xml:"Code"`
			Message string   `xml:"Message"`
		} `xml:"Error"`
	}

	result := DeleteResult{
		Deleted: make([]struct {
			XMLName      xml.Name `xml:"Deleted"`
			Key          string   `xml:"Key"`
			VersionID    string   `xml:"VersionId,omitempty"`
			DeleteMarker bool     `xml:"DeleteMarker,omitempty"`
		}, len(deleted)),
		Errors: make([]struct {
			XMLName xml.Name `xml:"Error"`
			Key     string   `xml:"Key"`
			Code    string   `xml:"Code"`
			Message string   `xml:"Message"`
		}, len(errors)),
	}

	for i, d := range deleted {
		result.Deleted[i].Key = d.Key
		if d.VersionID != "" {
			result.Deleted[i].VersionID = d.VersionID
		}
		if d.DeleteMarker {
			result.Deleted[i].DeleteMarker = true
		}
	}

	for i, e := range errors {
		result.Errors[i].Key = e.Key
		result.Errors[i].Code = e.Code
		result.Errors[i].Message = e.Message
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(result)

	h.metrics.RecordS3Operation("DeleteObjects", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest("POST", r.URL.Path, http.StatusOK, time.Since(start), 0)
}