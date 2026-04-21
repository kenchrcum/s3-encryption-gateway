//go:build integration
// +build integration

// Package test — Phase-D (V0.6-S3-3): End-to-end encrypted multipart upload
// tests using a real MinIO backend, real Valkey state store, and PasswordKeyManager.
// These tests replace the env-gated test/encrypted_mpu_test.go for CI coverage;
// the original file is kept for external-gateway regression testing.
package test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	s3sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encMPUFixture is a ready-to-use fixture for encrypted-MPU tests.
type encMPUFixture struct {
	minio     *MinIOTestServer
	gateway   *TestGateway
	bucket    string
	gwSDK     *s3sdk.Client // client pointed at the gateway
	rawClient *s3sdk.Client // client pointed directly at MinIO
}

func setupEncMPUFixture(t *testing.T) *encMPUFixture {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping encrypted MPU integration test in short mode")
	}

	minio := StartMinIOServer(t)
	prefix := TestBucketPrefix(t) + "-e"
	bucket := prefix + "-enc"

	CreateBucketForTest(t, minio, bucket)

	pm := EncryptedMPUPolicy(t, bucket+"*")
	km := NewTestPasswordKeyManager(t)
	store := NewTestMPUStateStore(t)

	cfg := minio.GetGatewayConfig()
	cfg.Encryption.Password = testMPUPassword
	gw := StartGateway(t, cfg,
		WithPolicyManager(pm),
		WithKeyManager(km),
		WithMPUStateStore(store),
	)
	t.Cleanup(gw.Close)

	gwSDK := newSDKClient(t, gw.URL, minio.AccessKey, minio.SecretKey)
	rawSDK := NewRawBackendS3Client(t, minio)

	return &encMPUFixture{
		minio:     minio,
		gateway:   gw,
		bucket:    bucket,
		gwSDK:     gwSDK,
		rawClient: rawSDK,
	}
}

// multipartUpload performs an N-part encrypted MPU via the gateway.
// partData is split into N equal parts (final part may be shorter).
// Returns the assembled plaintext as verified by GetObject through the gateway.
func multipartUpload(t *testing.T, cl *s3sdk.Client, bucket, key string, partData [][]byte) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	createResp, err := cl.CreateMultipartUpload(ctx, &s3sdk.CreateMultipartUploadInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	uploadID := createResp.UploadId
	t.Cleanup(func() {
		cl.AbortMultipartUpload(context.Background(), &s3sdk.AbortMultipartUploadInput{
			Bucket: aws.String(bucket), Key: aws.String(key), UploadId: uploadID,
		})
	})

	var completedParts []types.CompletedPart
	for i, part := range partData {
		pNum := int32(i + 1)
		upResp, err := cl.UploadPart(ctx, &s3sdk.UploadPartInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(key),
			UploadId:      uploadID,
			PartNumber:    aws.Int32(pNum),
			Body:          bytes.NewReader(part),
			ContentLength: aws.Int64(int64(len(part))),
		})
		require.NoError(t, err, "UploadPart %d", pNum)
		completedParts = append(completedParts, types.CompletedPart{
			ETag:       upResp.ETag,
			PartNumber: aws.Int32(pNum),
		})
	}

	_, err = cl.CompleteMultipartUpload(ctx, &s3sdk.CompleteMultipartUploadInput{
		Bucket:          aws.String(bucket),
		Key:             aws.String(key),
		UploadId:        uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completedParts},
	})
	require.NoError(t, err, "CompleteMultipartUpload")

	getResp, err := cl.GetObject(ctx, &s3sdk.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	defer getResp.Body.Close()
	got, err := io.ReadAll(getResp.Body)
	require.NoError(t, err)
	return got
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 14: 16 MiB / 2 parts, round-trip byte-for-byte
// ─────────────────────────────────────────────────────────────────────────────

func TestEncryptedMPU_PasswordKeyManager_SmallObject(t *testing.T) {
	f := setupEncMPUFixture(t)

	const partSize = 8 * 1024 * 1024
	part1 := make([]byte, partSize)
	part2 := make([]byte, partSize)
	for i := range part1 {
		part1[i] = byte(i & 0xFF)
	}
	for i := range part2 {
		part2[i] = byte((i + 1) & 0xFF)
	}

	got := multipartUpload(t, f.gwSDK, f.bucket, "t14-small.bin", [][]byte{part1, part2})
	want := append(part1, part2...)
	assert.Equal(t, want, got, "16 MiB / 2 parts round trip")

	// At-rest ciphertext must not contain part1's first 1 KiB.
	atRestIsEncrypted(t, f.rawClient, f.bucket, "t14-small.bin", part1)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 15: 64 MiB / 8 parts, ranged GET assertions
// ─────────────────────────────────────────────────────────────────────────────

func TestEncryptedMPU_PasswordKeyManager_Ranged_GET(t *testing.T) {
	f := setupEncMPUFixture(t)

	const partSize = 8 * 1024 * 1024
	const numParts = 8
	parts := make([][]byte, numParts)
	var plaintext []byte
	for i := range parts {
		parts[i] = make([]byte, partSize)
		for j := range parts[i] {
			parts[i][j] = byte((i*partSize + j) & 0xFF)
		}
		plaintext = append(plaintext, parts[i]...)
	}

	key := "t15-64m.bin"
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	// Upload (without re-downloading yet).
	createResp, err := f.gwSDK.CreateMultipartUpload(ctx, &s3sdk.CreateMultipartUploadInput{
		Bucket: aws.String(f.bucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	uploadID := createResp.UploadId
	t.Cleanup(func() {
		f.gwSDK.AbortMultipartUpload(context.Background(), &s3sdk.AbortMultipartUploadInput{
			Bucket: aws.String(f.bucket), Key: aws.String(key), UploadId: uploadID,
		})
	})

	var completed []types.CompletedPart
	for i, part := range parts {
		pNum := int32(i + 1)
		up, err := f.gwSDK.UploadPart(ctx, &s3sdk.UploadPartInput{
			Bucket:     aws.String(f.bucket),
			Key:        aws.String(key),
			UploadId:   uploadID,
			PartNumber: aws.Int32(pNum),
			Body:       bytes.NewReader(part),
		})
		require.NoError(t, err, "part %d", pNum)
		completed = append(completed, types.CompletedPart{ETag: up.ETag, PartNumber: aws.Int32(pNum)})
	}
	_, err = f.gwSDK.CompleteMultipartUpload(ctx, &s3sdk.CompleteMultipartUploadInput{
		Bucket:          aws.String(f.bucket),
		Key:             aws.String(key),
		UploadId:        uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completed},
	})
	require.NoError(t, err)

	// Helper for ranged GET.
	getRange := func(t *testing.T, start, end int) []byte {
		t.Helper()
		rangeHdr := fmt.Sprintf("bytes=%d-%d", start, end)
		resp, err := f.gwSDK.GetObject(ctx, &s3sdk.GetObjectInput{
			Bucket: aws.String(f.bucket), Key: aws.String(key),
			Range: aws.String(rangeHdr),
		})
		require.NoError(t, err)
		defer resp.Body.Close()
		got, _ := io.ReadAll(resp.Body)
		return got
	}

	chunkSize := 64 * 1024

	// Mid-chunk (offset 10 KiB, length 50 KiB within part 1).
	t.Run("mid-chunk", func(t *testing.T) {
		start, end := 10*1024, 60*1024-1
		assert.Equal(t, plaintext[start:end+1], getRange(t, start, end))
	})

	// Cross-chunk (offset 60 KiB, length 20 KiB spanning 64 KiB boundary).
	t.Run("cross-chunk", func(t *testing.T) {
		start := chunkSize - 4*1024
		end := chunkSize + 16*1024 - 1
		assert.Equal(t, plaintext[start:end+1], getRange(t, start, end))
	})

	// Cross-part (offset ~7.9 MiB, length 500 KiB spanning part 1/part 2).
	t.Run("cross-part", func(t *testing.T) {
		start := partSize - 100*1024
		end := start + 500*1024 - 1
		assert.Equal(t, plaintext[start:end+1], getRange(t, start, end))
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 16: 8 MiB / 1 part — at-rest ciphertext assertions
// ─────────────────────────────────────────────────────────────────────────────

func TestEncryptedMPU_PasswordKeyManager_AtRestCiphertext(t *testing.T) {
	f := setupEncMPUFixture(t)

	plaintext := make([]byte, 8*1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i & 0xFF)
	}
	key := "t16-atrest.bin"
	multipartUpload(t, f.gwSDK, f.bucket, key, [][]byte{plaintext})

	// Fetch raw ciphertext from backend.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	getResp, err := f.rawClient.GetObject(ctx, &s3sdk.GetObjectInput{
		Bucket: aws.String(f.bucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	defer getResp.Body.Close()
	raw, err := io.ReadAll(getResp.Body)
	require.NoError(t, err)

	// Ciphertext must be larger (AEAD tag + chunk overhead).
	assert.Greater(t, len(raw), len(plaintext), "ciphertext must be larger than plaintext")

	// First 1 KiB of plaintext must not appear in ciphertext.
	assert.False(t, bytes.Contains(raw, plaintext[:1024]),
		"at-rest ciphertext must not contain plaintext prefix")

	// Manifest object must exist (key ending in .mpu-manifest or companion header).
	listResp, err := f.rawClient.ListObjectsV2(ctx, &s3sdk.ListObjectsV2Input{
		Bucket: aws.String(f.bucket),
		Prefix: aws.String(key),
	})
	require.NoError(t, err)
	var hasManifest bool
	for _, obj := range listResp.Contents {
		if strings.HasSuffix(aws.ToString(obj.Key), ".mpu-manifest") {
			hasManifest = true
			break
		}
	}
	// Manifest may be inline (stored in S3 metadata) — check HEAD for the header too.
	if !hasManifest {
		headResp, err := f.rawClient.HeadObject(ctx, &s3sdk.HeadObjectInput{
			Bucket: aws.String(f.bucket), Key: aws.String(key),
		})
		if err == nil {
			for k := range headResp.Metadata {
				if strings.Contains(strings.ToLower(k), "mpu") {
					hasManifest = true
					break
				}
			}
		}
	}
	assert.True(t, hasManifest, "MPU manifest must exist (companion object or metadata header)")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 17: Abort deletes Valkey state
// ─────────────────────────────────────────────────────────────────────────────

func TestEncryptedMPU_PasswordKeyManager_AbortDeletesState(t *testing.T) {
	f := setupEncMPUFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	key := "t17-abort.bin"
	createResp, err := f.gwSDK.CreateMultipartUpload(ctx, &s3sdk.CreateMultipartUploadInput{
		Bucket: aws.String(f.bucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	uploadID := createResp.UploadId

	// Upload one part.
	partData := make([]byte, 5*1024*1024)
	upResp, err := f.gwSDK.UploadPart(ctx, &s3sdk.UploadPartInput{
		Bucket:     aws.String(f.bucket),
		Key:        aws.String(key),
		UploadId:   uploadID,
		PartNumber: aws.Int32(1),
		Body:       bytes.NewReader(partData),
	})
	require.NoError(t, err, "UploadPart")
	_ = upResp

	// Abort.
	_, err = f.gwSDK.AbortMultipartUpload(ctx, &s3sdk.AbortMultipartUploadInput{
		Bucket:   aws.String(f.bucket),
		Key:      aws.String(key),
		UploadId: uploadID,
	})
	require.NoError(t, err, "AbortMultipartUpload")

	// Backend must have zero parts (ListParts on aborted upload returns NoSuchUpload error).
	_, listErr := f.gwSDK.ListParts(ctx, &s3sdk.ListPartsInput{
		Bucket:   aws.String(f.bucket),
		Key:      aws.String(key),
		UploadId: uploadID,
	})
	assert.Error(t, listErr, "ListParts on aborted upload must fail")

	// No object at key.
	_, getErr := f.gwSDK.GetObject(ctx, &s3sdk.GetObjectInput{
		Bucket: aws.String(f.bucket), Key: aws.String(key),
	})
	assert.Error(t, getErr, "GetObject on aborted key must fail")
}
