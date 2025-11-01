package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/kenneth/s3-encryption-gateway/internal/config"
)

// Client is the S3 backend client interface.
type Client interface {
	PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string) error
	GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, map[string]string, error)
	DeleteObject(ctx context.Context, bucket, key string) error
	HeadObject(ctx context.Context, bucket, key string) (map[string]string, error)
	ListObjects(ctx context.Context, bucket, prefix string, opts ListOptions) ([]ObjectInfo, error)
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
}

// s3Client implements the Client interface using AWS SDK v2.
type s3Client struct {
	client *s3.Client
	config *config.BackendConfig
}

// NewClient creates a new S3 backend client.
func NewClient(cfg *config.BackendConfig) (Client, error) {
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

	// Configure endpoint for non-AWS providers
	s3Options := []func(*s3.Options){}
	if cfg.Endpoint != "" && cfg.Provider != "aws" {
		s3Options = append(s3Options, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		})
		awsCfg.BaseEndpoint = aws.String(cfg.Endpoint)
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
func (c *s3Client) GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, map[string]string, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	result, err := c.client.GetObject(ctx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get object %s/%s: %w", bucket, key, err)
	}

	metadata := extractMetadata(result.Metadata)

	return result.Body, metadata, nil
}

// DeleteObject deletes an object from S3.
func (c *s3Client) DeleteObject(ctx context.Context, bucket, key string) error {
	input := &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	_, err := c.client.DeleteObject(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to delete object %s/%s: %w", bucket, key, err)
	}

	return nil
}

// HeadObject retrieves object metadata without the body.
func (c *s3Client) HeadObject(ctx context.Context, bucket, key string) (map[string]string, error) {
	input := &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	result, err := c.client.HeadObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to head object %s/%s: %w", bucket, key, err)
	}

	metadata := extractMetadata(result.Metadata)

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