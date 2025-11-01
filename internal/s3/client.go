package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	
	"github.com/kenneth/s3-encryption-gateway/internal/config"
)

// Client is the S3 backend client interface.
type Client interface {
	PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string) error
	GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error)
	DeleteObject(ctx context.Context, bucket, key string, versionID *string) error
	HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error)
	ListObjects(ctx context.Context, bucket, prefix string, opts ListOptions) ([]ObjectInfo, error)
	
	// Multipart upload operations
	CreateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error)
	UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, reader io.Reader) (string, error)
	CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart) (string, error)
	AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error
	ListParts(ctx context.Context, bucket, key, uploadID string) ([]PartInfo, error)
	
	// Copy and batch operations
	CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string) (string, map[string]string, error)
	DeleteObjects(ctx context.Context, bucket string, keys []ObjectIdentifier) ([]DeletedObject, []ErrorObject, error)
}

// ListOptions holds options for listing objects.
type ListOptions struct {
	Delimiter string
	Marker    string
	MaxKeys   int32
}

// ObjectInfo holds information about an S3 object.
type ObjectInfo struct {
	Key          string
	Size         int64
	LastModified string
	ETag         string
	VersionID    string
}

// CompletedPart represents a completed part in a multipart upload.
type CompletedPart struct {
	PartNumber int32
	ETag       string
}

// PartInfo holds information about an upload part.
type PartInfo struct {
	PartNumber   int32
	ETag         string
	Size         int64
	LastModified string
}

// ObjectIdentifier identifies an object for deletion.
type ObjectIdentifier struct {
	Key       string
	VersionID string
}

// DeletedObject represents a successfully deleted object.
type DeletedObject struct {
	Key       string
	VersionID string
	DeleteMarker bool
}

// ErrorObject represents an error during batch delete.
type ErrorObject struct {
	Key       string
	Code      string
	Message   string
}

// s3Client implements the Client interface using AWS SDK v2.
type s3Client struct {
	client *s3.Client
	config *config.BackendConfig
}

// NewClient creates a new S3 backend client.
func NewClient(cfg *config.BackendConfig) (Client, error) {
	// Validate and normalize provider configuration
	endpoint, region, err := ValidateProviderConfig(cfg.Endpoint, cfg.Provider, cfg.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to validate provider config: %w", err)
	}

	// Validate endpoint URL
	if err := ValidateEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}

	// Use normalized region
	if region != "" {
		cfg.Region = region
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.AccessKey,
			cfg.SecretKey,
			"",
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Configure endpoint and options for all providers
	s3Options := []func(*s3.Options){}
	
	// Set endpoint for non-AWS providers or custom endpoints
	if endpoint != "" && (cfg.Provider != "aws" || !strings.Contains(endpoint, "amazonaws.com")) {
		s3Options = append(s3Options, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
		awsCfg.BaseEndpoint = aws.String(endpoint)
	}

	// Configure path-style addressing if required by provider
	if RequiresPathStyleAddressing(cfg.Provider) {
		s3Options = append(s3Options, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(awsCfg, s3Options...)

	return &s3Client{
		client: client,
		config: cfg,
	}, nil
}

// PutObject uploads an object to S3.
func (c *s3Client) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string) error {
	// Read the entire body (for now - will optimize for streaming later)
	body, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read object data: %w", err)
	}

	input := &s3.PutObjectInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		Body:     bytes.NewReader(body),
		Metadata: convertMetadata(metadata),
	}

	_, err = c.client.PutObject(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to put object %s/%s: %w", bucket, key, err)
	}

	return nil
}

// GetObject retrieves an object from S3.
func (c *s3Client) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	if versionID != nil && *versionID != "" {
		input.VersionId = versionID
	}

	if rangeHeader != nil && *rangeHeader != "" {
		input.Range = rangeHeader
	}

	result, err := c.client.GetObject(ctx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get object %s/%s: %w", bucket, key, err)
	}

	metadata := extractMetadata(result.Metadata)
	if result.VersionId != nil {
		metadata["x-amz-version-id"] = *result.VersionId
	}

	return result.Body, metadata, nil
}

// DeleteObject deletes an object from S3.
func (c *s3Client) DeleteObject(ctx context.Context, bucket, key string, versionID *string) error {
	input := &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	if versionID != nil && *versionID != "" {
		input.VersionId = versionID
	}

	_, err := c.client.DeleteObject(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to delete object %s/%s: %w", bucket, key, err)
	}

	return nil
}

// HeadObject retrieves object metadata without the body.
func (c *s3Client) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	input := &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	if versionID != nil && *versionID != "" {
		input.VersionId = versionID
	}

	result, err := c.client.HeadObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to head object %s/%s: %w", bucket, key, err)
	}

	metadata := extractMetadata(result.Metadata)
	if result.VersionId != nil {
		metadata["x-amz-version-id"] = *result.VersionId
	}
	if result.ContentLength != nil {
		metadata["Content-Length"] = fmt.Sprintf("%d", *result.ContentLength)
	}
	if result.ContentType != nil {
		metadata["Content-Type"] = *result.ContentType
	}
	if result.ETag != nil {
		metadata["ETag"] = *result.ETag
	}
	if result.LastModified != nil {
		metadata["Last-Modified"] = result.LastModified.Format("Mon, 02 Jan 2006 15:04:05 GMT")
	}

	return metadata, nil
}

// ListObjects lists objects in a bucket.
func (c *s3Client) ListObjects(ctx context.Context, bucket, prefix string, opts ListOptions) ([]ObjectInfo, error) {
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	}

	if opts.Delimiter != "" {
		input.Delimiter = aws.String(opts.Delimiter)
	}
	if opts.Marker != "" {
		input.ContinuationToken = aws.String(opts.Marker)
	}
	if opts.MaxKeys > 0 {
		input.MaxKeys = aws.Int32(opts.MaxKeys)
	}

	result, err := c.client.ListObjectsV2(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to list objects in bucket %s: %w", bucket, err)
	}

	objects := make([]ObjectInfo, 0, len(result.Contents))
	for _, obj := range result.Contents {
		objects = append(objects, ObjectInfo{
			Key:          aws.ToString(obj.Key),
			Size:         aws.ToInt64(obj.Size),
			LastModified: aws.ToTime(obj.LastModified).Format("2006-01-02T15:04:05.000Z"),
			ETag:         aws.ToString(obj.ETag),
		})
	}

	return objects, nil
}

// convertMetadata converts a map[string]string to AWS metadata format.
func convertMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return nil
	}
	return metadata
}

// extractMetadata extracts metadata from S3 response.
func extractMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return make(map[string]string)
	}
	return metadata
}

// CreateMultipartUpload initiates a multipart upload.
func (c *s3Client) CreateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error) {
	input := &s3.CreateMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		Metadata: convertMetadata(metadata),
	}

	result, err := c.client.CreateMultipartUpload(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to create multipart upload %s/%s: %w", bucket, key, err)
	}

	if result.UploadId == nil {
		return "", fmt.Errorf("upload ID not returned from backend")
	}

	return *result.UploadId, nil
}

// UploadPart uploads a part of a multipart upload.
func (c *s3Client) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, reader io.Reader) (string, error) {
	body, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("failed to read part data: %w", err)
	}

	input := &s3.UploadPartInput{
		Bucket:     aws.String(bucket),
		Key:        aws.String(key),
		UploadId:   aws.String(uploadID),
		PartNumber: aws.Int32(partNumber),
		Body:       bytes.NewReader(body),
	}

	result, err := c.client.UploadPart(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to upload part %d for %s/%s: %w", partNumber, bucket, key, err)
	}

	if result.ETag == nil {
		return "", fmt.Errorf("ETag not returned from backend")
	}

	return *result.ETag, nil
}

// CompleteMultipartUpload completes a multipart upload.
func (c *s3Client) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart) (string, error) {
	completedParts := make([]types.CompletedPart, len(parts))
	for i, p := range parts {
		completedParts[i] = types.CompletedPart{
			PartNumber: aws.Int32(p.PartNumber),
			ETag:       aws.String(p.ETag),
		}
	}

	input := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	}

	result, err := c.client.CompleteMultipartUpload(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to complete multipart upload %s/%s: %w", bucket, key, err)
	}

	if result.ETag == nil {
		return "", fmt.Errorf("ETag not returned from backend")
	}

	return *result.ETag, nil
}

// AbortMultipartUpload aborts a multipart upload.
func (c *s3Client) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	input := &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	}

	_, err := c.client.AbortMultipartUpload(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to abort multipart upload %s/%s: %w", bucket, key, err)
	}

	return nil
}

// ListParts lists the parts of a multipart upload.
func (c *s3Client) ListParts(ctx context.Context, bucket, key, uploadID string) ([]PartInfo, error) {
	input := &s3.ListPartsInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	}

	result, err := c.client.ListParts(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to list parts for %s/%s: %w", bucket, key, err)
	}

	parts := make([]PartInfo, 0, len(result.Parts))
	for _, p := range result.Parts {
		part := PartInfo{
			PartNumber: aws.ToInt32(p.PartNumber),
			ETag:       aws.ToString(p.ETag),
			Size:       aws.ToInt64(p.Size),
		}
		if p.LastModified != nil {
			part.LastModified = p.LastModified.Format("2006-01-02T15:04:05.000Z")
		}
		parts = append(parts, part)
	}

	return parts, nil
}

// CopyObject copies an object from source to destination.
func (c *s3Client) CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string) (string, map[string]string, error) {
	copySource := fmt.Sprintf("%s/%s", srcBucket, srcKey)
	if srcVersionID != nil && *srcVersionID != "" {
		copySource = fmt.Sprintf("%s/%s?versionId=%s", srcBucket, srcKey, *srcVersionID)
	}

	input := &s3.CopyObjectInput{
		Bucket:     aws.String(dstBucket),
		Key:        aws.String(dstKey),
		CopySource: aws.String(copySource),
		Metadata:   convertMetadata(metadata),
	}

	result, err := c.client.CopyObject(ctx, input)
	if err != nil {
		return "", nil, fmt.Errorf("failed to copy object from %s/%s to %s/%s: %w", srcBucket, srcKey, dstBucket, dstKey, err)
	}

	resultMetadata := make(map[string]string)
	if result.CopyObjectResult != nil {
		if result.CopyObjectResult.ETag != nil {
			resultMetadata["ETag"] = strings.Trim(*result.CopyObjectResult.ETag, "\"")
		}
		if result.CopyObjectResult.LastModified != nil {
			resultMetadata["Last-Modified"] = result.CopyObjectResult.LastModified.Format("Mon, 02 Jan 2006 15:04:05 GMT")
		}
	}

	etag := ""
	if result.CopyObjectResult != nil && result.CopyObjectResult.ETag != nil {
		etag = strings.Trim(*result.CopyObjectResult.ETag, "\"")
	}

	return etag, resultMetadata, nil
}

// DeleteObjects deletes multiple objects in a single request.
func (c *s3Client) DeleteObjects(ctx context.Context, bucket string, keys []ObjectIdentifier) ([]DeletedObject, []ErrorObject, error) {
	objects := make([]types.ObjectIdentifier, len(keys))
	for i, k := range keys {
		obj := types.ObjectIdentifier{
			Key: aws.String(k.Key),
		}
		if k.VersionID != "" {
			obj.VersionId = aws.String(k.VersionID)
		}
		objects[i] = obj
	}

	input := &s3.DeleteObjectsInput{
		Bucket: aws.String(bucket),
		Delete: &types.Delete{
			Objects: objects,
			Quiet:   aws.Bool(false), // Return both deleted and errors
		},
	}

	result, err := c.client.DeleteObjects(ctx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to delete objects in bucket %s: %w", bucket, err)
	}

	deleted := make([]DeletedObject, 0, len(result.Deleted))
	for _, d := range result.Deleted {
		deletedObj := DeletedObject{
			Key: aws.ToString(d.Key),
		}
		if d.VersionId != nil {
			deletedObj.VersionID = *d.VersionId
		}
		if d.DeleteMarker != nil {
			deletedObj.DeleteMarker = *d.DeleteMarker
		}
		deleted = append(deleted, deletedObj)
	}

	errors := make([]ErrorObject, 0, len(result.Errors))
	for _, e := range result.Errors {
		errorObj := ErrorObject{
			Key: aws.ToString(e.Key),
		}
		if e.Code != nil {
			errorObj.Code = *e.Code
		}
		if e.Message != nil {
			errorObj.Message = *e.Message
		}
		errors = append(errors, errorObj)
	}

	return deleted, errors, nil
}