package test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_EncryptedMultipartUpload(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") == "" {
		t.Skip("Skipping integration test; set RUN_INTEGRATION_TESTS=1 to run")
	}

	endpoint := os.Getenv("S3_GATEWAY_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("minioadmin", "minioadmin", "")),
		config.WithRegion("us-east-1"),
	)
	require.NoError(t, err)

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	bucket := "test-mpu-bucket"
	key := "test-mpu-object.bin"

	// 1. Create bucket (ignore error if exists)
	_, _ = client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	})

	// 2. Create MPU
	createResp, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err)
	uploadID := createResp.UploadId
	require.NotEmpty(t, uploadID)

	// 3. Upload Part
	partData := bytes.Repeat([]byte("A"), 5*1024*1024) // 5MB part
	uploadResp, err := client.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:     aws.String(bucket),
		Key:        aws.String(key),
		UploadId:   uploadID,
		PartNumber: aws.Int32(1),
		Body:       bytes.NewReader(partData),
	})
	require.NoError(t, err)
	etag := uploadResp.ETag
	require.NotEmpty(t, etag)

	// 4. Complete MPU
	_, err = client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{
				{
					ETag:       etag,
					PartNumber: aws.Int32(1),
				},
			},
		},
	})
	require.NoError(t, err)

	// 5. Abort an MPU
	createAbortResp, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key + ".abort"),
	})
	require.NoError(t, err)

	_, err = client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key + ".abort"),
		UploadId: createAbortResp.UploadId,
	})
	assert.NoError(t, err)
}
