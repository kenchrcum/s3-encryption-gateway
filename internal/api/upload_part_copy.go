package api

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/kenneth/s3-encryption-gateway/internal/s3"
	"github.com/sirupsen/logrus"
)

// SourceClass defines the type of encryption (if any) on the source object
// of an UploadPartCopy request. Each class maps to a distinct strategy in
// handleUploadPartCopy; see docs/adr/0006-upload-part-copy.md §Decision #3.
type SourceClass int

const (
	SourceClassPlaintext SourceClass = iota
	SourceClassChunked
	SourceClassLegacy
)

// String returns the short metric-safe label for a SourceClass.
func (c SourceClass) String() string {
	switch c {
	case SourceClassChunked:
		return "chunked"
	case SourceClassLegacy:
		return "legacy"
	default:
		return "plaintext"
	}
}

// CopySourceMetadata holds classification info for the source object.
type CopySourceMetadata struct {
	Class       SourceClass
	Size        int64
	IsChunked   bool
	IsEncrypted bool
}

// CopyPartResultXML is the XML response body for UploadPartCopy.
// See https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPartCopy.html
type CopyPartResultXML struct {
	XMLName      xml.Name `xml:"CopyPartResult"`
	ETag         string   `xml:"ETag"`
	LastModified string   `xml:"LastModified"`
}

// S3 per-part limits per
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html
const (
	// maxCopySourceSizeBytes is the S3-enforced upper bound on a single
	// UploadPartCopy source when no range is provided (5 GiB).
	maxCopySourceSizeBytes int64 = 5 * 1024 * 1024 * 1024
	// maxCopyPartRangeBytes is the maximum span of a single
	// x-amz-copy-source-range (5 GiB).
	maxCopyPartRangeBytes int64 = 5 * 1024 * 1024 * 1024
)

// handleUploadPartCopy handles UploadPartCopy requests (PUT with
// x-amz-copy-source header on a multipart part URL).
//
// Invariants preserved by this handler (see ADR 0006):
//  1. Destination parts are plaintext (ADR 0002). No per-part encryption.
//  2. Source-bucket READ authorisation is enforced implicitly because the
//     same caller-derived S3 client (from h.getS3Client(r)) performs the
//     HeadObject/GetObject. A caller without read access on the source
//     surfaces AccessDenied from the backend, which TranslateError maps to
//     HTTP 403.
//  3. If the destination bucket policy sets RequireEncryption=true and the
//     classified source is plaintext, the handler hard-refuses with 500
//     InternalError (destination-policy / source-mode mismatch) and emits
//     an audit event. This prevents silent security degradation from
//     config drift; see ADR 0006 §"Config Mismatch Detection".
//  4. The legacy fallback path is bounded by Server.MaxLegacyCopySourceBytes
//     (default 256 MiB, opt-out safety posture).
func (h *Handler) handleUploadPartCopy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]
	uploadID := vars["uploadId"]
	partNumberStr := vars["partNumber"]

	// These should already be validated in handleUploadPart, but double-check.
	if bucket == "" || key == "" || uploadID == "" || partNumberStr == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Check if multipart uploads are disabled.
	if h.config != nil && h.config.Server.DisableMultipartUploads {
		s3Err := &S3Error{
			Code:       "NotImplemented",
			Message:    "Multipart uploads are disabled",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusNotImplemented,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
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
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	// Get S3 client. This binds to the caller's credentials when
	// UseClientCredentials is enabled, which is the mechanism by which
	// source-bucket read authorisation is enforced: the caller MUST be
	// authorised to read the source, or the backend returns AccessDenied.
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "PUT", start)
		return
	}

	// Parse x-amz-copy-source header.
	copySource := r.Header.Get("x-amz-copy-source")
	if copySource == "" {
		s3Err := &S3Error{
			Code:       "InvalidArgument",
			Message:    "Missing x-amz-copy-source header",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	srcBucket, srcKey, srcVersionID, err := parseCopySource(copySource)
	if err != nil {
		s3Err := &S3Error{
			Code:       "InvalidArgument",
			Message:    "Invalid x-amz-copy-source header",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Parse optional x-amz-copy-source-range header.
	var srcRange *s3.CopyPartRange
	rangeHeader := r.Header.Get("x-amz-copy-source-range")
	if rangeHeader != "" {
		start64, end64, perr := crypto.ParseHTTPRangeHeader(rangeHeader, -1)
		if perr != nil {
			s3Err := &S3Error{
				Code:       "InvalidArgument",
				Message:    "Invalid x-amz-copy-source-range header",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusBadRequest,
			}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
			return
		}
		if end64-start64+1 > maxCopyPartRangeBytes {
			s3Err := &S3Error{
				Code:       "InvalidRequest",
				Message:    "The specified copy-source-range exceeds the maximum allowable size (5 GiB)",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusBadRequest,
			}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
			return
		}
		srcRange = &s3.CopyPartRange{
			First: start64,
			Last:  end64,
		}
	}

	// Classify the source object. This issues a single HeadObject using the
	// caller's credentials, so an unauthorised caller gets AccessDenied
	// (HTTP 403) from the backend — this is the source-bucket READ
	// authorisation gate.
	sourceClass, err := h.classifyCopySource(ctx, s3Client, srcBucket, srcKey, srcVersionID)
	if err != nil {
		s3Err := TranslateError(err, srcBucket, srcKey)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"src_bucket": srcBucket,
			"src_key":    srcKey,
		}).Error("Failed to classify copy source")
		// Source-scoped error: record with the source bucket label for
		// debuggability.
		h.metrics.RecordS3Error(r.Context(), "UploadPartCopy", srcBucket, s3Err.Code)
		h.metrics.RecordUploadPartCopy("unknown", "error", 0, time.Since(start))
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Enforce 5 GiB cap on source size when no range is provided.
	// S3 requires UploadPartCopy with source > 5 GiB to specify a range.
	if srcRange == nil && sourceClass.Size > 0 && sourceClass.Size > maxCopySourceSizeBytes {
		s3Err := &S3Error{
			Code:       "InvalidRequest",
			Message:    "The specified copy source is larger than the maximum allowable size for a copy source: 5368709120. Specify x-amz-copy-source-range.",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordUploadPartCopy(sourceClass.Class.String(), "error", 0, time.Since(start))
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Destination-policy / source-mode mismatch hard-refusal:
	// if the destination bucket policy mandates encryption but the source
	// is classified as plaintext, refuse. The plaintext fast path would
	// otherwise silently upload unencrypted bytes into a bucket policy says
	// must be encrypted. Per ADR 0006 §"Config Mismatch Detection" and
	// Real-World Cryptography (Wong, 2021) Ch. 16.
	if sourceClass.Class == SourceClassPlaintext && h.policyManager != nil && h.policyManager.BucketRequiresEncryption(bucket) {
		msg := "Destination bucket requires encryption but copy source is plaintext"
		h.logger.WithFields(logrus.Fields{
			"src_bucket": srcBucket,
			"src_key":    srcKey,
			"dst_bucket": bucket,
			"dst_key":    key,
		}).Error(msg)
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Destination bucket configuration requires encryption but the copy source is not encrypted.",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		// Audit the refusal so operators see config-drift incidents.
		if h.auditLogger != nil {
			h.auditLogger.LogAccessWithMetadata(
				"copy_part_refused", bucket, key,
				getClientIP(r), r.UserAgent(), getRequestID(r),
				false, fmt.Errorf("%s", msg), time.Since(start),
				map[string]interface{}{
					"src_bucket":  srcBucket,
					"src_key":     srcKey,
					"src_version": versionIDValue(srcVersionID),
					"src_mode":    "plaintext",
					"upload_id":   uploadID,
					"part_number": partNumber,
					"reason":      "destination_requires_encryption",
				},
			)
		}
		h.metrics.RecordS3Error(r.Context(), "UploadPartCopy", bucket, s3Err.Code)
		h.metrics.RecordUploadPartCopy("plaintext", "error", 0, time.Since(start))
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Execute the appropriate strategy based on source class.
	var (
		copyResult   *s3.CopyPartResult
		strategyErr  error
		bytesCopied  int64
		sourceMode   = sourceClass.Class.String()
		maxLegacyCap = effectiveMaxLegacyCopySourceBytes(h.config)
	)

	switch sourceClass.Class {
	case SourceClassPlaintext:
		copyResult, strategyErr = s3Client.UploadPartCopy(ctx, bucket, key, uploadID, int32(partNumber),
			srcBucket, srcKey, srcVersionID, srcRange)
		if strategyErr == nil {
			bytesCopied = plaintextCopiedBytes(srcRange, sourceClass.Size)
		}

	case SourceClassChunked:
		copyResult, bytesCopied, strategyErr = h.uploadPartCopyChunked(ctx, s3Client, bucket, key, uploadID, int32(partNumber),
			srcBucket, srcKey, srcVersionID, srcRange)

	case SourceClassLegacy:
		copyResult, bytesCopied, strategyErr = h.uploadPartCopyLegacy(ctx, s3Client, bucket, key, uploadID, int32(partNumber),
			srcBucket, srcKey, srcVersionID, srcRange, sourceClass.Size, maxLegacyCap)
	}

	if strategyErr != nil {
		s3Err := TranslateError(strategyErr, bucket, key)
		// Promote sentinel errors to specific S3 codes.
		if isLegacySourceTooLarge(strategyErr) {
			s3Err = &S3Error{
				Code: "InvalidRequest",
				Message: fmt.Sprintf(
					"Legacy-encrypted copy source exceeds the gateway's in-memory cap (%d bytes). "+
						"Migrate the source to chunked encryption, or raise Server.MaxLegacyCopySourceBytes with adequate pod memory.",
					maxLegacyCap),
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusBadRequest,
			}
		} else if isRangeNotSatisfiable(strategyErr) {
			s3Err = &S3Error{
				Code:       "InvalidRange",
				Message:    "The requested range is not satisfiable",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusRequestedRangeNotSatisfiable,
			}
		}
		s3Err.WriteXML(w)
		h.logger.WithError(strategyErr).WithFields(logrus.Fields{
			"bucket":      bucket,
			"key":         key,
			"uploadID":    uploadID,
			"partNumber":  partNumber,
			"srcBucket":   srcBucket,
			"srcKey":      srcKey,
			"source_mode": sourceMode,
			"duration_ms": time.Since(start).Milliseconds(),
		}).Error("UploadPartCopy strategy failed")
		h.metrics.RecordS3Error(r.Context(), "UploadPartCopy", bucket, s3Err.Code)
		h.metrics.RecordUploadPartCopy(sourceMode, "error", 0, time.Since(start))
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Log successful copy with structured fields.
	h.logger.WithFields(logrus.Fields{
		"src_bucket":   srcBucket,
		"src_key":      srcKey,
		"src_version":  versionIDValue(srcVersionID),
		"src_range":    formatRangeForLog(srcRange),
		"src_mode":     sourceMode,
		"dst_bucket":   bucket,
		"dst_key":      key,
		"upload_id":    uploadID,
		"part_number":  partNumber,
		"dst_etag":     copyResult.ETag,
		"bytes_copied": bytesCopied,
		"duration_ms":  time.Since(start).Milliseconds(),
	}).Info("UploadPartCopy completed")

	// Record metrics.
	h.metrics.RecordS3Operation(r.Context(), "UploadPartCopy", bucket, time.Since(start))
	h.metrics.RecordUploadPartCopy(sourceMode, "ok", bytesCopied, time.Since(start))

	// Audit the successful copy with full metadata.
	if h.auditLogger != nil {
		auditMetadata := map[string]interface{}{
			"src_bucket":   srcBucket,
			"src_key":      srcKey,
			"src_version":  versionIDValue(srcVersionID),
			"src_mode":     sourceMode,
			"upload_id":    uploadID,
			"part_number":  partNumber,
			"dst_etag":     copyResult.ETag,
			"bytes_copied": bytesCopied,
		}
		if srcRange != nil {
			auditMetadata["src_range"] = map[string]int64{"first": srcRange.First, "last": srcRange.Last}
		}
		h.auditLogger.LogAccessWithMetadata(
			"copy_part", bucket, key,
			getClientIP(r), r.UserAgent(), getRequestID(r),
			true, nil, time.Since(start), auditMetadata,
		)
	}

	// Return CopyPartResult XML.
	result := CopyPartResultXML{
		ETag:         copyResult.ETag,
		LastModified: copyResult.LastModified.UTC().Format("2006-01-02T15:04:05.000Z"),
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_ = xml.NewEncoder(w).Encode(result)

	h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// classifyCopySource determines the encryption class of the source object
// using a single HeadObject call. The HeadObject is issued with the
// caller's credentials (via the provided s3Client), so unauthorised callers
// surface AccessDenied here and short-circuit the copy.
func (h *Handler) classifyCopySource(ctx context.Context, s3Client s3.Client, bucket, key string, versionID *string) (*CopySourceMetadata, error) {
	metadata, err := s3Client.HeadObject(ctx, bucket, key, versionID)
	if err != nil {
		return nil, err
	}

	sourceClass := &CopySourceMetadata{
		Class: SourceClassPlaintext,
	}

	if metadata[crypto.MetaChunkedFormat] == "true" {
		sourceClass.Class = SourceClassChunked
		sourceClass.IsChunked = true
		sourceClass.IsEncrypted = true
	} else if metadata[crypto.MetaEncrypted] == "true" {
		sourceClass.Class = SourceClassLegacy
		sourceClass.IsEncrypted = true
	}

	// Object size is available from Content-Length or OriginalSize (chunked)
	// depending on the source format.
	if sizeStr, ok := metadata["Content-Length"]; ok {
		if size, err := strconv.ParseInt(sizeStr, 10, 64); err == nil {
			sourceClass.Size = size
		}
	}
	if sourceClass.Size == 0 {
		if origSize, ok := metadata[crypto.MetaOriginalSize]; ok {
			if size, err := strconv.ParseInt(origSize, 10, 64); err == nil {
				sourceClass.Size = size
			}
		}
	}

	return sourceClass, nil
}

// uploadPartCopyChunked handles UploadPartCopy for chunked-encrypted sources.
// DecryptRange is invoked with absolute plaintext offsets; it seeks within
// the encrypted stream using the manifest carried in metadata. Bounded
// memory: one chunk + transfer buffer (chunk size ≤ 1 MiB per chunked.go).
func (h *Handler) uploadPartCopyChunked(ctx context.Context, s3Client s3.Client,
	dstBucket, dstKey, uploadID string, partNumber int32,
	srcBucket, srcKey string, srcVersionID *string, srcRange *s3.CopyPartRange,
) (*s3.CopyPartResult, int64, error) {

	srcEngine, err := h.getEncryptionEngine(srcBucket)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get source encryption engine: %w", err)
	}

	srcMetadata, err := s3Client.HeadObject(ctx, srcBucket, srcKey, srcVersionID)
	if err != nil {
		return nil, 0, err
	}

	// Determine plaintext range. When no source range is specified, copy
	// the full object (bounded by plaintext size from metadata).
	plaintextSize, _ := crypto.GetPlaintextSizeFromMetadata(srcMetadata)
	var plaintextStart, plaintextEnd int64
	if srcRange != nil {
		plaintextStart = srcRange.First
		plaintextEnd = srcRange.Last
		// Explicit 416 for out-of-range source-range against chunked sources.
		if plaintextSize > 0 && plaintextStart >= plaintextSize {
			return nil, 0, errRangeNotSatisfiable
		}
		// Clamp end to last valid byte (AWS behaviour).
		if plaintextSize > 0 && plaintextEnd >= plaintextSize {
			plaintextEnd = plaintextSize - 1
		}
	} else {
		if plaintextSize <= 0 {
			return nil, 0, fmt.Errorf("cannot determine plaintext size for chunked source")
		}
		plaintextStart = 0
		plaintextEnd = plaintextSize - 1
	}

	// Translate plaintext range to encrypted byte range.
	encryptedStart, encryptedEnd, err := crypto.CalculateEncryptedRangeForPlaintextRange(srcMetadata, plaintextStart, plaintextEnd)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to calculate encrypted range: %w", err)
	}

	// Fetch encrypted range from backend.
	encryptedRangeHeader := fmt.Sprintf("bytes=%d-%d", encryptedStart, encryptedEnd)
	srcReader, _, err := s3Client.GetObject(ctx, srcBucket, srcKey, srcVersionID, &encryptedRangeHeader)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get source object range: %w", err)
	}
	defer srcReader.Close()

	// DecryptRange uses the manifest in metadata to seek within the encrypted
	// stream and emits plaintext for the requested absolute range.
	decryptedReader, _, err := srcEngine.DecryptRange(srcReader, srcMetadata, plaintextStart, plaintextEnd)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decrypt range: %w", err)
	}

	etag, err := s3Client.UploadPart(ctx, dstBucket, dstKey, uploadID, partNumber, decryptedReader, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to upload part: %w", err)
	}

	bytesCopied := plaintextEnd - plaintextStart + 1
	return &s3.CopyPartResult{
		ETag:         etag,
		LastModified: time.Now(),
	}, bytesCopied, nil
}

// uploadPartCopyLegacy handles UploadPartCopy for legacy (non-chunked)
// encrypted sources. Must buffer the full object in memory because legacy
// format is a single AEAD stream that cannot be range-decrypted. Bounded
// by Server.MaxLegacyCopySourceBytes (default 256 MiB, opt-out safety
// posture — see ADR 0006 §"Why Legacy Fallback Has a Configurable Cap").
func (h *Handler) uploadPartCopyLegacy(ctx context.Context, s3Client s3.Client,
	dstBucket, dstKey, uploadID string, partNumber int32,
	srcBucket, srcKey string, srcVersionID *string, srcRange *s3.CopyPartRange,
	srcSizeHint int64, maxLegacyCap int64,
) (*s3.CopyPartResult, int64, error) {

	// Pre-flight cap check using the Content-Length from classification if
	// available. Avoids starting a large download we will refuse.
	if srcSizeHint > 0 && srcSizeHint > maxLegacyCap {
		return nil, 0, errLegacySourceTooLarge
	}

	srcEngine, err := h.getEncryptionEngine(srcBucket)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get source encryption engine: %w", err)
	}

	srcReader, srcMetadata, err := s3Client.GetObject(ctx, srcBucket, srcKey, srcVersionID, nil)
	if err != nil {
		return nil, 0, err
	}
	defer srcReader.Close()

	decryptedReader, _, err := srcEngine.Decrypt(srcReader, srcMetadata)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decrypt source object: %w", err)
	}

	// Bounded read: refuse anything beyond the cap even if the backend
	// reported a smaller Content-Length (defensive — backends can lie).
	// ReadAll up to cap+1 then check; +1 lets us distinguish "exactly at cap"
	// from "over cap".
	limited := io.LimitReader(decryptedReader, maxLegacyCap+1)
	plaintextData, err := io.ReadAll(limited)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read decrypted source: %w", err)
	}
	if int64(len(plaintextData)) > maxLegacyCap {
		return nil, 0, errLegacySourceTooLarge
	}

	if h.logger != nil {
		h.logger.WithFields(logrus.Fields{
			"src_bucket":        srcBucket,
			"src_key":           srcKey,
			"object_size_bytes": len(plaintextData),
			"max_cap_bytes":     maxLegacyCap,
		}).Warn("UploadPartCopy using legacy (non-chunked) source; full-object decryption required (slow path)")
	}

	// Slice the requested range if provided.
	var partData []byte
	if srcRange != nil {
		if srcRange.First >= int64(len(plaintextData)) {
			return nil, 0, errRangeNotSatisfiable
		}
		end := srcRange.Last + 1
		if end > int64(len(plaintextData)) {
			end = int64(len(plaintextData))
		}
		partData = plaintextData[srcRange.First:end]
	} else {
		partData = plaintextData
	}

	etag, err := s3Client.UploadPart(ctx, dstBucket, dstKey, uploadID, partNumber, bytes.NewReader(partData), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to upload part: %w", err)
	}

	return &s3.CopyPartResult{
		ETag:         etag,
		LastModified: time.Now(),
	}, int64(len(partData)), nil
}

// --- sentinel errors & helpers ---

var (
	errLegacySourceTooLarge = fmt.Errorf("legacy copy source exceeds gateway cap")
	errRangeNotSatisfiable  = fmt.Errorf("range not satisfiable")
)

func isLegacySourceTooLarge(err error) bool {
	return err != nil && errors.Is(err, errLegacySourceTooLarge)
}

func isRangeNotSatisfiable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errRangeNotSatisfiable) {
		return true
	}
	// Also catch the string emitted by engine.DecryptRange for out-of-range
	// source-range against chunked sources.
	return strings.Contains(err.Error(), "range not satisfiable")
}

// effectiveMaxLegacyCopySourceBytes returns the configured cap, falling back
// to the conservative default (256 MiB) if unconfigured or ≤ 0.
func effectiveMaxLegacyCopySourceBytes(cfg *config.Config) int64 {
	if cfg != nil && cfg.Server.MaxLegacyCopySourceBytes > 0 {
		return cfg.Server.MaxLegacyCopySourceBytes
	}
	return config.DefaultMaxLegacyCopySourceBytes
}

// plaintextCopiedBytes returns the number of plaintext bytes a plaintext-
// fast-path copy transferred. Used for the bytes_total metric. When the
// backend performed the copy and we don't have authoritative sizing, we
// approximate from the range or Content-Length.
func plaintextCopiedBytes(srcRange *s3.CopyPartRange, srcSize int64) int64 {
	if srcRange != nil {
		return srcRange.Last - srcRange.First + 1
	}
	if srcSize > 0 {
		return srcSize
	}
	return 0
}

// formatRangeForLog formats a CopyPartRange for structured logging.
func formatRangeForLog(r *s3.CopyPartRange) string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("bytes=%d-%d", r.First, r.Last)
}

// versionIDValue dereferences an optional version ID for log/audit output.
func versionIDValue(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
