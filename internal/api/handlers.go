package api

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/kenneth/s3-encryption-gateway/internal/audit"
	"github.com/kenneth/s3-encryption-gateway/internal/cache"
	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/kenneth/s3-encryption-gateway/internal/metrics"
	"github.com/kenneth/s3-encryption-gateway/internal/s3"
	"github.com/sirupsen/logrus"
)

// Handler handles HTTP requests for S3 operations.
type Handler struct {
	s3Client        s3.Client // Legacy: kept for backward compatibility
	clientFactory   *s3.ClientFactory // New: factory for per-request clients
	encryptionEngine crypto.EncryptionEngine
	logger          *logrus.Logger
	metrics         *metrics.Metrics
	keyManager      crypto.KeyManager
	cache           cache.Cache
	auditLogger     audit.Logger
	config          *config.Config
}

// NewHandler creates a new API handler (backward compatibility).
func NewHandler(s3Client s3.Client, encryptionEngine crypto.EncryptionEngine, logger *logrus.Logger, m *metrics.Metrics) *Handler {
	return NewHandlerWithFeatures(s3Client, encryptionEngine, logger, m, nil, nil, nil, nil)
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
	config *config.Config,
) *Handler {
    h := &Handler{
		s3Client:        s3Client,
		encryptionEngine: encryptionEngine,
		logger:          logger,
		metrics:         m,
		keyManager:     keyManager,
		cache:          cache,
		auditLogger:    auditLogger,
		config:         config,
    }
    // Create client factory for per-request credential support
    if config != nil {
        h.clientFactory = s3.NewClientFactory(&config.Backend)
    }
    // If key manager is available, wire a key resolver into the encryption engine for rotation support.
    if keyManager != nil {
        crypto.SetKeyResolver(encryptionEngine, func(version int) (string, bool) {
            pass, err := keyManager.GetKeyVersion(version)
            if err != nil || pass == "" {
                return "", false
            }
            return pass, true
        })
    }
    return h
}

// RegisterRoutes registers all API routes.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/health", h.handleHealth).Methods("GET")
	r.HandleFunc("/ready", h.handleReady).Methods("GET")
	r.HandleFunc("/live", h.handleLive).Methods("GET")

	// S3 API routes
	s3Router := r.PathPrefix("/").Subrouter()

	// Multipart upload routes (must be registered first to ensure query parameter matching)
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handleCreateMultipartUpload).Methods("POST").Queries("uploads", "")
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handleCompleteMultipartUpload).Methods("POST").Queries("uploadId", "{uploadId}")
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handleAbortMultipartUpload).Methods("DELETE").Queries("uploadId", "{uploadId}")
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handleListParts).Methods("GET").Queries("uploadId", "{uploadId}")

	// Multipart-specific PUT route
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handleUploadPart).Methods("PUT").Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId}")

	// Generic S3 routes
	s3Router.HandleFunc("/{bucket}", h.handleListObjects).Methods("GET")
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handleGetObject).Methods("GET")
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handlePutObject).Methods("PUT")
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handleDeleteObject).Methods("DELETE")
	s3Router.HandleFunc("/{bucket}/{key:.*}", h.handleHeadObject).Methods("HEAD")

	// Batch operations
	s3Router.HandleFunc("/{bucket}", h.handleDeleteObjects).Methods("POST").Queries("delete", "")
}

// writeS3ClientError writes an appropriate S3 error response for client initialization failures.
func (h *Handler) writeS3ClientError(w http.ResponseWriter, r *http.Request, err error, method string, start time.Time) {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}

	// When use_client_credentials is enabled, provide specific error messages
	if h.config != nil && h.config.Backend.UseClientCredentials {
		var s3Err *S3Error
		
		// Check if this is a Signature V4 limitation
		if strings.Contains(errMsg, "Signature V4") {
			s3Err = &S3Error{
				Code:       "SignatureDoesNotMatch",
				Message:    "Signature V4 authentication is not supported when use_client_credentials is enabled. " +
					"The signature includes the Host header, which prevents forwarding requests to the backend. " +
					"Please use query parameter authentication (AWSAccessKeyId and AWSSecretAccessKey in URL) instead. " +
					"For AWS CLI, you may need to use a custom client that supports query parameter authentication.",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusForbidden,
			}
		} else if strings.Contains(errMsg, "failed to extract credentials") || strings.Contains(errMsg, "incomplete") {
			// Missing or incomplete credentials
			s3Err = &S3Error{
				Code:       "AccessDenied",
				Message:    "Missing or invalid credentials in request. " +
					"When use_client_credentials is enabled, credentials must be provided via query parameters " +
					"(AWSAccessKeyId and AWSSecretAccessKey) or Authorization header.",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusForbidden,
			}
		} else {
			// Generic credential error
			s3Err = &S3Error{
				Code:       "AccessDenied",
				Message:    "Failed to authenticate request: " + errMsg,
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusForbidden,
			}
		}
		
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(method, r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}
	
	// Otherwise return InternalError (when use_client_credentials is not enabled)
	s3Err := &S3Error{
		Code:       "InternalError",
		Message:    "Failed to initialize S3 client: " + errMsg,
		Resource:   r.URL.Path,
		HTTPStatus: http.StatusInternalServerError,
	}
	s3Err.WriteXML(w)
	h.metrics.RecordHTTPRequest(method, r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
}

// forwardSignatureV4Request forwards a Signature V4 request directly to the backend,
// preserving the original Authorization header and other headers.
func (h *Handler) forwardSignatureV4Request(w http.ResponseWriter, r *http.Request, method, bucket, key string, start time.Time) {
	if h.config == nil || h.config.Backend.Endpoint == "" {
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Backend endpoint not configured",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(method, r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Build backend URL
	backendEndpoint := h.config.Backend.Endpoint
	if !strings.HasPrefix(backendEndpoint, "http://") && !strings.HasPrefix(backendEndpoint, "https://") {
		if h.config.Backend.UseSSL {
			backendEndpoint = "https://" + backendEndpoint
		} else {
			backendEndpoint = "http://" + backendEndpoint
		}
	}
	backendEndpoint = strings.TrimSuffix(backendEndpoint, "/")

	// For Signature V4 forwarding, always use path-style addressing
	// This is more compatible when forwarding signed requests because:
	// 1. The Host header can remain as the gateway's hostname (for signature validation)
	// 2. The backend endpoint hostname is used for the actual connection
	// 3. Path-style is more forgiving with Host header mismatches
	backendPath := fmt.Sprintf("/%s", bucket)
	if key != "" {
		backendPath = fmt.Sprintf("/%s/%s", bucket, key)
	}
	backendURL := backendEndpoint + backendPath

	if r.URL.RawQuery != "" {
		if strings.Contains(backendURL, "?") {
			backendURL += "&" + r.URL.RawQuery
		} else {
			backendURL += "?" + r.URL.RawQuery
		}
	}

	// Create request to backend
	backendReq, err := http.NewRequestWithContext(r.Context(), method, backendURL, r.Body)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create backend request")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to forward request",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(method, r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Extract backend hostname from URL
	backendURLParsed, err := url.Parse(backendURL)
	if err == nil {
		backendHostname := backendURLParsed.Host
		
		// For Signature V4, the signature includes the Host header
		// We need to use the backend's hostname, but this may cause signature validation to fail
		// Some S3-compatible backends are lenient and will accept it
		// Copy all headers from original request (including Authorization)
		for k, v := range r.Header {
			// Skip Host - we'll set it to backend hostname
			if strings.EqualFold(k, "Host") {
				continue
			}
			backendReq.Header[k] = v
		}
		
		// Set Host to backend hostname (without port if default)
		backendReq.Host = backendHostname
		h.logger.WithFields(logrus.Fields{
			"original_host": r.Host,
			"backend_host":  backendHostname,
		}).Debug("Setting Host header to backend hostname for Signature V4 forwarding")
	} else {
		// Fallback: preserve original Host if URL parsing fails
		originalHost := r.Host
		if originalHost == "" {
			originalHost = r.Header.Get("Host")
		}
		for k, v := range r.Header {
			backendReq.Header[k] = v
		}
		backendReq.Host = originalHost
	}

	// Set Content-Length if present
	if r.ContentLength > 0 {
		backendReq.ContentLength = r.ContentLength
	}

	// Log forwarding details for debugging
	originalHost := r.Host
	if originalHost == "" {
		originalHost = r.Header.Get("Host")
	}
	h.logger.WithFields(logrus.Fields{
		"backend_url":  backendURL,
		"original_host": originalHost,
		"backend_host": backendReq.Host,
		"method":       method,
	}).Debug("Forwarding Signature V4 request to backend")

	// Make request to backend
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	backendResp, err := httpClient.Do(backendReq)
	if err != nil {
		h.logger.WithError(err).Error("Failed to forward request to backend")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to connect to backend",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadGateway,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(method, r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}
	defer backendResp.Body.Close()

	// Log backend response for debugging
	h.logger.WithFields(logrus.Fields{
		"status_code": backendResp.StatusCode,
		"backend_url": backendURL,
	}).Debug("Backend response received")

	// If backend returned an error, log the response body
	if backendResp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(backendResp.Body)
		backendResp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		h.logger.WithFields(logrus.Fields{
			"status_code": backendResp.StatusCode,
			"response":   string(bodyBytes),
		}).Warn("Backend returned error response")
	}

	// Check if response is encrypted (before copying headers)
	metadata := make(map[string]string)
	if backendResp.StatusCode >= 200 && backendResp.StatusCode < 300 && method == "GET" {
		for k, v := range backendResp.Header {
			if len(v) > 0 {
				// Convert header names to lowercase for metadata check
				metadata[strings.ToLower(k)] = v[0]
			}
		}
	}

	isEncrypted := h.encryptionEngine.IsEncrypted(metadata)
	var decMetadata map[string]string
	var decryptedReader io.Reader

	if isEncrypted && backendResp.StatusCode >= 200 && backendResp.StatusCode < 300 && method == "GET" {
		// Try to decrypt - read body first, then decrypt
		bodyBytes, err := io.ReadAll(backendResp.Body)
		if err == nil {
			decryptedReader, decMetadata, err = h.encryptionEngine.Decrypt(bytes.NewReader(bodyBytes), metadata)
			if err != nil {
				h.logger.WithError(err).Warn("Failed to decrypt forwarded response, returning as-is")
				isEncrypted = false // Fall back to forwarding encrypted
				backendResp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			} else {
				backendResp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}
		} else {
			isEncrypted = false
		}
	}

	// Copy response headers (before WriteHeader)
	for k, v := range backendResp.Header {
		// Skip headers that shouldn't be forwarded
		if strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		// Remove encryption metadata if we decrypted
		if isEncrypted && strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
			continue
		}
		w.Header()[k] = v
	}

	// Update headers if we decrypted
	if isEncrypted && decMetadata != nil {
		if cl, ok := decMetadata["Content-Length"]; ok {
			w.Header().Set("Content-Length", cl)
		}
		// Add decrypted metadata
		for k, v := range decMetadata {
			if strings.HasPrefix(k, "x-amz-meta-") {
				w.Header().Set(k, v)
			}
		}
	}

	// Write status code
	w.WriteHeader(backendResp.StatusCode)

	// Write response body
	if isEncrypted && decryptedReader != nil {
		io.Copy(w, decryptedReader)
	} else {
		io.Copy(w, backendResp.Body)
	}

	// Record metrics - use 0 if ContentLength is unknown (-1)
	contentLength := backendResp.ContentLength
	if contentLength < 0 {
		contentLength = 0
	}
	h.metrics.RecordHTTPRequest(method, r.URL.Path, backendResp.StatusCode, time.Since(start), contentLength)
}

// getS3Client returns the appropriate S3 client for the request.
// If use_client_credentials is enabled, extracts credentials from request and creates a client.
// For Signature V4 requests, returns nil to indicate request should be forwarded directly.
// Otherwise, returns the default configured client.
func (h *Handler) getS3Client(r *http.Request) (s3.Client, error) {
	// If credential passthrough is not enabled, use default client
	if h.config == nil || !h.config.Backend.UseClientCredentials {
		if h.s3Client != nil {
			return h.s3Client, nil
		}
		if h.clientFactory != nil {
			return h.clientFactory.GetClient()
		}
		return nil, fmt.Errorf("no S3 client available")
	}

	// When use_client_credentials is enabled, check for Signature V4
	// Signature V4 requests include the Host header in the signature, so forwarding doesn't work
	// because the signature was created for the gateway's hostname, not the backend's
	if IsSignatureV4Request(r) {
		clientCreds, err := ExtractCredentials(r)
		if err == nil && clientCreds.AccessKey != "" {
			// Return a helpful error explaining the limitation
			h.logger.WithFields(logrus.Fields{
				"access_key": clientCreds.AccessKey,
			}).Warn("Signature V4 requests cannot be forwarded - signature validation will fail")
			return nil, fmt.Errorf("Signature V4 requests are not supported when use_client_credentials is enabled. " +
				"The signature includes the Host header, so forwarding to the backend fails validation. " +
				"Please use query parameter authentication (AWSAccessKeyId and AWSSecretAccessKey in URL) instead, " +
				"or configure the client to use query parameters rather than Signature V4")
		}
	}

	// Try to extract credentials (for query parameters or other methods)
	clientCreds, err := ExtractCredentials(r)
	if err != nil {
		h.logger.WithError(err).Warn("Failed to extract client credentials from request")
		return nil, fmt.Errorf("failed to extract credentials from request: %w", err)
	}

	// Both access key and secret key are required for non-Signature V4 requests
	if clientCreds.AccessKey == "" {
		h.logger.Warn("Client credentials incomplete: missing access key")
		return nil, fmt.Errorf("client credentials incomplete: missing access key")
	}

	if clientCreds.SecretKey == "" {
		h.logger.WithFields(logrus.Fields{
			"access_key": clientCreds.AccessKey,
		}).Warn("Client credentials incomplete: missing secret key")
		return nil, fmt.Errorf("client credentials incomplete: missing secret key")
	}

	// Create client with extracted credentials
	if h.clientFactory == nil {
		return nil, fmt.Errorf("client factory not initialized")
	}

	client, err := h.clientFactory.GetClientWithCredentials(clientCreds.AccessKey, clientCreds.SecretKey)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"access_key": clientCreds.AccessKey,
		}).Error("Failed to create client with extracted credentials")
		return nil, fmt.Errorf("failed to create S3 client with client credentials: %w", err)
	}

	h.logger.WithFields(logrus.Fields{
		"access_key": clientCreds.AccessKey,
	}).Debug("Using client credentials for backend request")
	return client, nil
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

	h.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key": key,
	}).Debug("Starting GET object")

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

    // If Range is requested, optimize for chunked encryption format
    // For chunked encryption: calculate encrypted byte range and fetch only needed chunks
    // For legacy/buffered encryption: fetch full object, decrypt, then apply range
    var backendRange *string
    var useRangeOptimization bool
    var plaintextStart, plaintextEnd int64
    
    // Get S3 client (may use client credentials if enabled)
    // For Signature V4 requests, s3Client may be nil - we'll forward the request directly
    s3Client, err := h.getS3Client(r)
    if err != nil {
        h.logger.WithError(err).Error("Failed to get S3 client")
        h.writeS3ClientError(w, r, err, "GET", start)
        return
    }

    // If s3Client is nil, this indicates Signature V4 was detected and can't be handled
    if s3Client == nil && err == nil {
        // This shouldn't happen - getS3Client should return an error for Signature V4
        // But handle it gracefully just in case
        s3Err := &S3Error{
            Code:       "NotImplemented",
            Message:    "Signature V4 requests are not supported. Please use query parameter authentication instead.",
            Resource:   r.URL.Path,
            HTTPStatus: http.StatusNotImplemented,
        }
        s3Err.WriteXML(w)
        h.metrics.RecordHTTPRequest("GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
        return
    }

    if rangeHeader != nil {
        // Check if object is encrypted and uses chunked format
        headMeta, headErr := s3Client.HeadObject(ctx, bucket, key, versionID)
        if headErr == nil && h.encryptionEngine.IsEncrypted(headMeta) {
            // Check if chunked format - if so, we can optimize by fetching only needed chunks
            if crypto.IsChunkedFormat(headMeta) {
                // Get plaintext size for range parsing
                plaintextSize, err := crypto.GetPlaintextSizeFromMetadata(headMeta)
                if err == nil {
                    // Parse range header to get plaintext byte range
                    start, end, err := crypto.ParseHTTPRangeHeader(*rangeHeader, plaintextSize)
                    if err == nil {
                        plaintextStart, plaintextEnd = start, end
                       	// Calculate encrypted byte range for needed chunks
                       	encryptedStart, encryptedEnd, err := crypto.CalculateEncryptedRangeForPlaintextRange(headMeta, start, end)
                       	if err == nil {
                           	// Format as HTTP Range header
                           	encryptedRange := fmt.Sprintf("bytes=%d-%d", encryptedStart, encryptedEnd)
                           	backendRange = &encryptedRange
                           	useRangeOptimization = true
                           	h.logger.WithFields(logrus.Fields{
                           		"bucket":         bucket,
                           		"key":            key,
                           		"plaintext_range": fmt.Sprintf("%d-%d", start, end),
                           		"encrypted_range": encryptedRange,
                           	}).Debug("Using optimized range request for chunked encryption")
                       	} else {
                           	h.logger.WithError(err).Warn("Failed to calculate encrypted range, falling back to full fetch")
                           	backendRange = nil
                       	}
                    } else {
                       	h.logger.WithError(err).Warn("Failed to parse range header, falling back to full fetch")
                       	backendRange = nil
                    }
                } else {
                   	h.logger.WithError(err).Warn("Failed to get plaintext size, falling back to full fetch")
                   	backendRange = nil
                }
            } else {
                // Legacy format: must fetch full object
                backendRange = nil
            }
        } else {
            // Not encrypted or HEAD failed: forward range to backend
            backendRange = rangeHeader
        }
    }

    reader, metadata, err := s3Client.GetObject(ctx, bucket, key, versionID, backendRange)
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

	h.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key": key,
		"is_encrypted": h.encryptionEngine.IsEncrypted(metadata),
	}).Debug("GET object retrieved from backend")

	// Decrypt if encrypted
	decryptStart := time.Now()
	var decryptedReader io.Reader
	var decMetadata map[string]string
	
	if useRangeOptimization && h.encryptionEngine.IsEncrypted(metadata) {
		// Use range-optimized decryption (only decrypts needed chunks)
		// Access the concrete engine type for DecryptRange method
		// This is safe because we know it's chunked format
		if eng, ok := h.encryptionEngine.(interface {
			DecryptRange(reader io.Reader, metadata map[string]string, plaintextStart, plaintextEnd int64) (io.Reader, map[string]string, error)
		}); ok {
			decryptedReader, decMetadata, err = eng.DecryptRange(reader, metadata, plaintextStart, plaintextEnd)
			if err != nil {
				h.logger.WithError(err).Warn("Range optimization failed, falling back to full decrypt")
				// Fall back to full decryption
				decryptedReader, decMetadata, err = h.encryptionEngine.Decrypt(reader, metadata)
				useRangeOptimization = false
			}
		} else {
			// Engine doesn't support DecryptRange, fall back
			h.logger.Warn("Engine doesn't support DecryptRange, falling back to full decrypt")
			decryptedReader, decMetadata, err = h.encryptionEngine.Decrypt(reader, metadata)
			useRangeOptimization = false
		}
	} else {
		// Standard decryption (full object)
		decryptedReader, decMetadata, err = h.encryptionEngine.Decrypt(reader, metadata)
	}
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

    // For range optimization, we already have the exact range in decryptedReader
    // For non-optimized ranges, we need to buffer and apply range
    var decryptedData []byte
    var decryptedSize int64
    if rangeHeader != nil && *rangeHeader != "" && !useRangeOptimization {
        // Buffer for range processing (only if not using optimization)
        dd, err := io.ReadAll(decryptedReader)
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
        decryptedData = dd
        decryptedSize = int64(len(decryptedData))
    } else if useRangeOptimization {
        // For optimized range, the reader already contains only the range
        // But we still need to read it to send it
        decryptedSize = plaintextEnd - plaintextStart + 1
    }
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
        if useRangeOptimization {
            // Optimized range: decryptedReader already contains only the range
            // Read it into outputData
            outputData, err = io.ReadAll(decryptedReader)
            if err != nil {
                h.logger.WithError(err).Error("Failed to read optimized range data")
                s3Err := &S3Error{
                    Code:       "InternalError",
                    Message:    "Failed to read range data",
                    Resource:   r.URL.Path,
                    HTTPStatus: http.StatusInternalServerError,
                }
                s3Err.WriteXML(w)
                h.metrics.RecordHTTPRequest("GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
                return
            }
            
            // Get total size for Content-Range header
            totalSize, _ := crypto.GetPlaintextSizeFromMetadata(metadata)
            if totalSize == 0 {
                // Fallback to approximate from decryptedData if available
                totalSize = int64(len(decryptedData))
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
            w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", plaintextStart, plaintextEnd, totalSize))
            w.Header().Set("Content-Length", fmt.Sprintf("%d", len(outputData)))
            w.WriteHeader(http.StatusPartialContent)
        } else {
            // Non-optimized: apply range to buffered data
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

            // Parse the original range to get correct Content-Range header
            rangeStart, rangeEnd, err := crypto.ParseHTTPRangeHeader(*rangeHeader, int64(len(decryptedData)))
            if err != nil {
                // This shouldn't happen since applyRangeRequest succeeded, but handle gracefully
                h.logger.WithError(err).Warn("Failed to parse range header for Content-Range")
                rangeStart, rangeEnd = 0, int64(len(outputData)-1)
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
            w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rangeStart, rangeEnd, len(decryptedData)))
            w.Header().Set("Content-Length", fmt.Sprintf("%d", len(outputData)))
            w.WriteHeader(http.StatusPartialContent)
        }
    } else {
        // Set decrypted metadata headers and stream body
        for k, v := range decMetadata {
            if !isEncryptionMetadata(k) {
                w.Header().Set(k, v)
            }
        }
        if versionID != nil && *versionID != "" {
            w.Header().Set("x-amz-version-id", *versionID)
        }
        w.WriteHeader(http.StatusOK)
        n64, err := io.Copy(w, decryptedReader)
        if err != nil {
            h.logger.WithError(err).Error("Failed to write response")
            h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), n64)
            return
        }
        h.metrics.RecordS3Operation("GetObject", bucket, time.Since(start))
        h.metrics.RecordHTTPRequest("GET", r.URL.Path, http.StatusOK, time.Since(start), n64)
        return
    }

    // For ranged responses, write buffered bytes
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

	h.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key": key,
	}).Debug("Starting PUT object")

	if bucket == "" || key == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest("PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "PUT", start)
		return
	}

	// Check if this is a copy operation
	copySource := r.Header.Get("x-amz-copy-source")
	if copySource != "" {
		// Handle copy operation (pass s3Client)
		h.handleCopyObject(w, r, bucket, key, copySource, start, s3Client)
		return
	}

	// Extract metadata from headers (preserve original metadata)
	// Only include x-amz-meta-* headers - standard headers should NOT be included
	// as they will cause S3 API errors when sent as metadata
	metadata := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			// Only include x-amz-meta-* headers, not standard headers like Content-Length
			if len(k) > 11 && k[:11] == "x-amz-meta-" {
				metadata[k] = v[0]
			}
		}
	}

	// Store original content length if available (as x-amz-meta- header)
	var originalBytes int64
	if contentLength := r.Header.Get("Content-Length"); contentLength != "" {
		metadata["x-amz-meta-original-content-length"] = contentLength
		fmt.Sscanf(contentLength, "%d", &originalBytes)
	}
	
	// Extract Content-Type for encryption engine (for compression decisions)
	// The encryption engine reads it from metadata, but we'll filter it out before S3
	// This is a temporary inclusion - filterS3Metadata will remove it
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream" // Default to match MinIO's behavior
	}
	metadata["Content-Type"] = contentType

    // Include key version in metadata if key manager is enabled
    if h.keyManager != nil {
        _, keyVersion, _ := h.keyManager.GetActiveKey()
        if keyVersion > 0 {
            metadata[crypto.MetaKeyVersion] = fmt.Sprintf("%d", keyVersion)
        }
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

    // Record encryption metrics using original bytes
    h.metrics.RecordEncryptionOperation("encrypt", encryptDuration, originalBytes)

    // Debug logging for metadata before upload
    h.logger.WithFields(logrus.Fields{
        "bucket": bucket,
        "key":    key,
        "metadata_keys": len(encMetadata),
    }).Debug("Uploading encrypted object with metadata")
    
    // Log all metadata keys for debugging (don't log values for security)
    metadataKeys := make([]string, 0, len(encMetadata))
    for k := range encMetadata {
        metadataKeys = append(metadataKeys, k)
        // Check for potentially problematic values
        if v, ok := encMetadata[k]; ok && v == "0" {
            h.logger.WithFields(logrus.Fields{
                "metadata_key": k,
                "value": v,
            }).Warn("Metadata contains zero value - may cause S3 rejection")
        }
    }
    h.logger.WithFields(logrus.Fields{
        "bucket":       bucket,
        "key":          key,
        "metadata_keys": metadataKeys,
    }).Debug("Metadata keys before filtering")

    // Filter out standard HTTP headers from metadata before sending to S3
    // S3 metadata should only contain x-amz-meta-* headers, not standard headers like Content-Length
    var filterKeys []string
    if h.config != nil {
        filterKeys = h.config.Backend.FilterMetadataKeys
    }
    s3Metadata := filterS3Metadata(encMetadata, filterKeys)

	h.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key": key,
	}).Debug("PUT object encrypted successfully")
    // Log filtered metadata keys and value sizes for debugging
    filteredKeys := make([]string, 0, len(s3Metadata))
    metadataSizes := make(map[string]int)
    for k, v := range s3Metadata {
        filteredKeys = append(filteredKeys, k)
        metadataSizes[k] = len(v)
        // S3 metadata values are limited to 2KB per AWS docs, but some providers may be stricter
        if len(v) > 2048 {
            h.logger.WithFields(logrus.Fields{
                "bucket":      bucket,
                "key":         key,
                "metadata_key": k,
                "value_size":  len(v),
            }).Warn("Metadata value exceeds 2KB - may cause S3 rejection")
        }
    }
    h.logger.WithFields(logrus.Fields{
        "bucket":        bucket,
        "key":           key,
        "metadata_keys": filteredKeys,
        "metadata_sizes": metadataSizes,
    }).Debug("Metadata keys after filtering (being sent to S3)")

    // Compute encrypted content length for chunked mode if possible to avoid chunked transfer
    var contentLengthPtr *int64
    if encMetadata[crypto.MetaChunkedFormat] == "true" && originalBytes > 0 {
        // Determine chunk size from metadata
        chunkSize := crypto.DefaultChunkSize
        if csStr, ok := encMetadata[crypto.MetaChunkSize]; ok && csStr != "" {
            var cs int
            if _, err := fmt.Sscanf(csStr, "%d", &cs); err == nil && cs > 0 {
                chunkSize = cs
            }
        }
        // AEAD tag size for AES-GCM and ChaCha20-Poly1305 is 16 bytes
        const aeadTagSize = 16
        chunkCount := (originalBytes + int64(chunkSize) - 1) / int64(chunkSize)
        encLen := originalBytes + chunkCount*int64(aeadTagSize)
        contentLengthPtr = &encLen
    }

    // Upload encrypted object with filtered metadata (streaming)
    err = s3Client.PutObject(ctx, bucket, key, encryptedReader, s3Metadata, contentLengthPtr)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
			"metadata_keys": metadataKeys,
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
        "Content-Encoding": true,
        "Content-Language": true,
        "Content-Disposition": true,
        "Last-Modified": true,
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
	
	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "DELETE", start)
		return
	}

	// Extract version ID if provided
	var versionID *string
	if vid := r.URL.Query().Get("versionId"); vid != "" {
		versionID = &vid
	}

	err = s3Client.DeleteObject(ctx, bucket, key, versionID)
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
	
	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "HEAD", start)
		return
	}

	// Extract version ID if provided
	var versionID *string
	if vid := r.URL.Query().Get("versionId"); vid != "" {
		versionID = &vid
	}

	metadata, err := s3Client.HeadObject(ctx, bucket, key, versionID)
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
		// Chunked encryption metadata
		"x-amz-meta-encryption-chunked",
		"x-amz-meta-encryption-chunk-size",
		"x-amz-meta-encryption-chunk-count",
		"x-amz-meta-encryption-manifest",
		// Original content length (set by gateway)
		"x-amz-meta-original-content-length",
	}
	for _, ek := range encryptionKeys {
		if key == ek {
			return true
		}
	}
	return false
}

// filterS3Metadata filters out standard HTTP headers from metadata map.
// S3 metadata should only contain x-amz-meta-* headers, not standard headers
// like Content-Length, Content-Type, ETag, etc. which some S3 providers reject.
// Additionally filters out any keys specified in filterKeys for backend compatibility.
func filterS3Metadata(metadata map[string]string, filterKeys []string) map[string]string {
	s3Metadata := make(map[string]string)

	// Create a set of keys to filter out for efficient lookup
	filterSet := make(map[string]bool)
	if filterKeys != nil {
		for _, key := range filterKeys {
			filterSet[key] = true
		}
	}
	for k, v := range metadata {
		// Only include x-amz-meta-* headers as S3 metadata

		// Skip keys that should be filtered out for backend compatibility
		if filterSet[k] {
			continue
		}
		if len(k) > 11 && k[:11] == "x-amz-meta-" {
			s3Metadata[k] = v
		} else if !isStandardMetadata(k) {
			// Include non-standard headers that aren't standard HTTP headers
			// (though typically only x-amz-meta-* should be here)
			s3Metadata[k] = v
		}
		// Explicitly exclude standard headers: Content-Length, Content-Type, ETag, etc.
	}
	return s3Metadata
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

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "GET", start)
		return
	}

	prefix := r.URL.Query().Get("prefix")
	delimiter := r.URL.Query().Get("delimiter")
	continuationToken := r.URL.Query().Get("continuation-token")
	maxKeys := int32(1000) // Default
	if mk := r.URL.Query().Get("max-keys"); mk != "" {
		fmt.Sscanf(mk, "%d", &maxKeys)
	}

	opts := s3.ListOptions{
		Delimiter:         delimiter,
		ContinuationToken: continuationToken,
		MaxKeys:           maxKeys,
	}

	listResult, err := s3Client.ListObjects(ctx, bucket, prefix, opts)
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

	// Translate metadata for encrypted objects
	translatedObjects := make([]s3.ObjectInfo, len(listResult.Objects))
	for i, obj := range listResult.Objects {
		translatedObjects[i] = obj
		// If object is encrypted, translate size and ETag
		if h.encryptionEngine.IsEncrypted(map[string]string{}) {
			// We need to fetch HEAD metadata for each object to get encryption info
			// This is expensive but necessary for accurate listings
			if headMeta, headErr := s3Client.HeadObject(ctx, bucket, obj.Key, nil); headErr == nil {
				if h.encryptionEngine.IsEncrypted(headMeta) {
					// Restore original size
					if originalSize, ok := headMeta["x-amz-meta-encryption-original-size"]; ok {
						if parsedSize, err := strconv.ParseInt(originalSize, 10, 64); err == nil {
							translatedObjects[i].Size = parsedSize
						}
					} else if originalSize, ok := headMeta["x-amz-meta-original-content-length"]; ok {
						if parsedSize, err := strconv.ParseInt(originalSize, 10, 64); err == nil {
							translatedObjects[i].Size = parsedSize
						}
					}
					// Restore original ETag
					if originalETag, ok := headMeta["x-amz-meta-encryption-original-etag"]; ok {
						translatedObjects[i].ETag = originalETag
					}
				}
			}
		}
	}

	// Generate proper S3 ListBucketResult XML response
	xmlResponse := generateListObjectsXML(bucket, prefix, delimiter, translatedObjects, listResult.CommonPrefixes, listResult.NextContinuationToken, listResult.IsTruncated)

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
func generateListObjectsXML(bucket, prefix, delimiter string, objects []s3.ObjectInfo, commonPrefixes []string, nextContinuationToken string, isTruncated bool) string {
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
	xml.WriteString(fmt.Sprintf("  <IsTruncated>%t</IsTruncated>\n", isTruncated))

	// Add continuation token if present
	if nextContinuationToken != "" {
		xml.WriteString(fmt.Sprintf("  <NextContinuationToken>%s</NextContinuationToken>\n", nextContinuationToken))
	}

	// Add objects
	for _, obj := range objects {
		xml.WriteString("  <Contents>\n")
		xml.WriteString(fmt.Sprintf("    <Key>%s</Key>\n", obj.Key))
		xml.WriteString(fmt.Sprintf("    <LastModified>%s</LastModified>\n", obj.LastModified))
		xml.WriteString(fmt.Sprintf("    <ETag>%s</ETag>\n", obj.ETag))
		xml.WriteString(fmt.Sprintf("    <Size>%d</Size>\n", obj.Size))
		xml.WriteString("    <StorageClass>STANDARD</StorageClass>\n")
		xml.WriteString("  </Contents>\n")
	}

	// Add common prefixes
	for _, cp := range commonPrefixes {
		xml.WriteString("  <CommonPrefixes>\n")
		xml.WriteString(fmt.Sprintf("    <Prefix>%s</Prefix>\n", cp))
		xml.WriteString("  </CommonPrefixes>\n")
	}

	xml.WriteString("</ListBucketResult>")
	return xml.String()
}

// handleCreateMultipartUpload handles multipart upload initiation.
func (h *Handler) handleCreateMultipartUpload(w http.ResponseWriter, r *http.Request) {
    // Multipart uploads are now supported with chunked encryption
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

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "POST", start)
		return
	}

	// Extract metadata from headers
	metadata := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			// Only include x-amz-meta-* headers as S3 metadata
			// Standard headers should not be sent as metadata
			if len(k) > 11 && k[:11] == "x-amz-meta-" {
				metadata[k] = v[0]
			}
		}
	}

	uploadID, err := s3Client.CreateMultipartUpload(ctx, bucket, key, metadata)
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

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "PUT", start)
		return
	}

	// Encrypt the part data
	metadata := make(map[string]string)
	var originalBytes int64
	if contentLength := r.Header.Get("Content-Length"); contentLength != "" {
		if parsed, parseErr := strconv.ParseInt(contentLength, 10, 64); parseErr == nil && parsed >= 0 {
			originalBytes = parsed
		} else {
			h.logger.WithError(parseErr).WithFields(logrus.Fields{
				"bucket":   bucket,
				"key":      key,
				"uploadID": uploadID,
			}).Warn("Invalid Content-Length for upload part; proceeding without content length optimization")
		}
	}

	encryptedReader, encMetadata, err := h.encryptionEngine.Encrypt(r.Body, metadata)
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

	// Provide encrypted content length when possible to avoid SDK re-reads
	var contentLengthPtr *int64
	if originalBytes > 0 {
		const aeadTagSize = 16
		if encMetadata[crypto.MetaChunkedFormat] == "true" {
			chunkSize := crypto.DefaultChunkSize
			if csStr := encMetadata[crypto.MetaChunkSize]; csStr != "" {
				if cs, err := strconv.Atoi(csStr); err == nil && cs > 0 {
					chunkSize = cs
				}
			}
			chunkCount := (originalBytes + int64(chunkSize) - 1) / int64(chunkSize)
			encLen := originalBytes + chunkCount*int64(aeadTagSize)
			contentLengthPtr = &encLen
		} else if encMetadata[crypto.MetaEncrypted] == "true" {
			encLen := originalBytes + int64(aeadTagSize)
			contentLengthPtr = &encLen
		}
	}

	etag, err := s3Client.UploadPart(ctx, bucket, key, uploadID, int32(partNumber), encryptedReader, contentLengthPtr)
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
    // Multipart uploads are now supported with chunked encryption
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

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "POST", start)
		return
	}

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

	etag, err := s3Client.CompleteMultipartUpload(ctx, bucket, key, uploadID, parts)
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

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "DELETE", start)
		return
	}

	err = s3Client.AbortMultipartUpload(ctx, bucket, key, uploadID)
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
    // Multipart uploads are now supported
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

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "GET", start)
		return
	}

	parts, err := s3Client.ListParts(ctx, bucket, key, uploadID)
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
func (h *Handler) handleCopyObject(w http.ResponseWriter, r *http.Request, dstBucket, dstKey, copySource string, start time.Time, s3Client s3.Client) {
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
	srcReader, srcMetadata, err := s3Client.GetObject(ctx, srcBucket, srcKey, srcVersionID, nil)
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

	// Preserve Content-Type from source object if not specified in copy request
	if _, hasContentType := dstMetadata["Content-Type"]; !hasContentType {
		if srcContentType, ok := srcMetadata["Content-Type"]; ok {
			dstMetadata["Content-Type"] = srcContentType
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

    // Filter out standard HTTP headers from metadata before sending to S3
    var filterKeys []string
    if h.config != nil {
        filterKeys = h.config.Backend.FilterMetadataKeys
    }
    s3Metadata := filterS3Metadata(encMetadata, filterKeys)

    // Upload encrypted copy with filtered metadata and known content length
    encLen := int64(len(encryptedData))
    err = s3Client.PutObject(ctx, dstBucket, dstKey, bytes.NewReader(encryptedData), s3Metadata, &encLen)
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
    headMeta, _ := s3Client.HeadObject(ctx, dstBucket, dstKey, nil)
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

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "POST", start)
		return
	}

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

	deleted, errors, err := s3Client.DeleteObjects(ctx, bucket, identifiers)
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

