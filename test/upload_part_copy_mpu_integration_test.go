//go:build integration
// +build integration

// Package test — Phase-C (V0.6-S3-3): UploadPartCopy into encrypted-MPU
// destinations (Phase E re-encrypt code path in upload_part_copy.go).
package test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	s3sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// upcMPUFixture adds encrypted-MPU state (Valkey, PasswordKeyManager) on top
// of the basic upcFixture. Tests 11-13 use this extended fixture.
type upcMPUFixture struct {
	*upcFixture
	mpuSDK *s3sdk.Client // points at the encrypted-MPU-enabled gateway
}

func setupUPCMPUFixture(t *testing.T) *upcMPUFixture {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping UploadPartCopy MPU integration test in short mode")
	}

	minio := StartMinIOServer(t)
	prefix := TestBucketPrefix(t) + "-m"
	srcBucket := prefix + "-src"
	dstBucket := prefix + "-dst"

	CreateBucketForTest(t, minio, srcBucket)
	CreateBucketForTest(t, minio, dstBucket)
	rawS3, err := minio.GetS3Client()
	require.NoError(t, err)
	ctx := context.Background()
	rawSDKClient := NewRawBackendS3Client(t, minio)

	// Policy: src bucket gets chunked engine; dst bucket gets encrypted MPU.
	pm := NewTestPolicyManager(t,
		fmt.Sprintf("id: mpu-src\nbuckets: [\"%s*\"]\nencryption:\n  password: \"%s\"\n", srcBucket, upcSrcPass),
		fmt.Sprintf("id: mpu-dst\nbuckets: [\"%s*\"]\nencrypt_multipart_uploads: true\nencryption:\n  password: \"%s\"\n", dstBucket, testMPUPassword),
	)

	km := NewTestPasswordKeyManager(t)
	store := NewTestMPUStateStore(t)

	cfg := minio.GetGatewayConfig()
	cfg.Encryption.Password = upcSrcPass
	gw := StartGateway(t, cfg,
		WithPolicyManager(pm),
		WithKeyManager(km),
		WithMPUStateStore(store),
	)
	t.Cleanup(gw.Close)

	sdkClient := newSDKClient(t, gw.URL, minio.AccessKey, minio.SecretKey)

	// Source data: 512 KiB of incrementing bytes.
	const srcSize = 512 * 1024
	srcData := make([]byte, srcSize)
	for i := range srcData {
		srcData[i] = byte(i & 0xFF)
	}

	// Seed plaintext source (no encryption).
	plainKey := "mpu-plaintext-src.bin"
	_, err = rawSDKClient.PutObject(ctx, &s3sdk.PutObjectInput{
		Bucket:        aws.String(srcBucket),
		Key:           aws.String(plainKey),
		Body:          bytes.NewReader(srcData),
		ContentLength: aws.Int64(int64(len(srcData))),
	})
	require.NoError(t, err)

	// Seed chunked source directly on backend (see fixture comment).
	chunkedEngine, err := crypto.NewEngineWithChunking(upcSrcPass, nil, "", nil, true, crypto.DefaultChunkSize)
	require.NoError(t, err)
	chunkedKey := "mpu-chunked-src.bin"
	chEncReader, chEncMeta, err := chunkedEngine.Encrypt(bytes.NewReader(srcData), map[string]string{})
	require.NoError(t, err)
	chEncBytes, err := io.ReadAll(chEncReader)
	require.NoError(t, err)
	chEncLen := int64(len(chEncBytes))
	require.NoError(t, rawS3.PutObject(ctx, srcBucket, chunkedKey, bytes.NewReader(chEncBytes), chEncMeta, &chEncLen, "", nil))

	// Seed legacy source: encrypt with legacy engine + PUT to backend.
	legacyEngine, err := crypto.NewEngine(upcSrcPass)
	require.NoError(t, err)
	legacyKey := "mpu-legacy-src.bin"
	encReader, encMeta, err := legacyEngine.Encrypt(bytes.NewReader(srcData), map[string]string{"Content-Type": "application/octet-stream"})
	require.NoError(t, err)
	encBytes, err := io.ReadAll(encReader)
	require.NoError(t, err)
	require.NoError(t, rawS3.PutObject(ctx, srcBucket, legacyKey, bytes.NewReader(encBytes), encMeta, nil, "", nil))

	base := &upcFixture{
		minioServer:     minio,
		srcBucket:       srcBucket,
		dstBucket:       dstBucket,
		gateway:         gw,
		gwSDK:           sdkClient,
		rawClient:       rawSDKClient,
		srcPlaintextKey: plainKey,
		srcChunkedKey:   chunkedKey,
		srcLegacyKey:    legacyKey,
		srcData:         srcData,
	}
	return &upcMPUFixture{upcFixture: base, mpuSDK: sdkClient}
}

// encryptedMPUCopy creates an MPU on dstBucket, does one UploadPartCopy from
// copySource (with optional range), completes, and returns downloaded bytes.
func encryptedMPUCopy(t *testing.T, cl *s3sdk.Client, dstBucket, dstKey, copySource string, copySourceRange *string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	createResp, err := cl.CreateMultipartUpload(ctx, &s3sdk.CreateMultipartUploadInput{
		Bucket: aws.String(dstBucket), Key: aws.String(dstKey),
	})
	require.NoError(t, err)
	uploadID := createResp.UploadId
	t.Cleanup(func() {
		cl.AbortMultipartUpload(context.Background(), &s3sdk.AbortMultipartUploadInput{
			Bucket: aws.String(dstBucket), Key: aws.String(dstKey), UploadId: uploadID,
		})
	})

	upcIn := &s3sdk.UploadPartCopyInput{
		Bucket:     aws.String(dstBucket),
		Key:        aws.String(dstKey),
		UploadId:   uploadID,
		PartNumber: aws.Int32(1),
		CopySource: aws.String(copySource),
	}
	if copySourceRange != nil {
		upcIn.CopySourceRange = copySourceRange
	}
	upcResp, err := cl.UploadPartCopy(ctx, upcIn)
	require.NoError(t, err)
	require.NotNil(t, upcResp.CopyPartResult)

	_, err = cl.CompleteMultipartUpload(ctx, &s3sdk.CompleteMultipartUploadInput{
		Bucket:   aws.String(dstBucket),
		Key:      aws.String(dstKey),
		UploadId: uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{
				{ETag: upcResp.CopyPartResult.ETag, PartNumber: aws.Int32(1)},
			},
		},
	})
	require.NoError(t, err)

	getResp, err := cl.GetObject(ctx, &s3sdk.GetObjectInput{
		Bucket: aws.String(dstBucket), Key: aws.String(dstKey),
	})
	require.NoError(t, err)
	defer getResp.Body.Close()
	got, err := io.ReadAll(getResp.Body)
	require.NoError(t, err)
	return got
}

// atRestIsEncrypted checks that the raw backend bytes for bucket/key do NOT
// contain the first 1 KiB of plaintext.
func atRestIsEncrypted(t *testing.T, cl *s3sdk.Client, bucket, key string, plaintext []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	getResp, err := cl.GetObject(ctx, &s3sdk.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	require.NoError(t, err, "raw backend GetObject for at-rest check")
	defer getResp.Body.Close()
	raw, err := io.ReadAll(getResp.Body)
	require.NoError(t, err)
	probe := plaintext
	if len(probe) > 1024 {
		probe = probe[:1024]
	}
	assert.False(t, bytes.Contains(raw, probe),
		"at-rest ciphertext must not contain first 1 KiB of plaintext")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 11: plaintext source → encrypted MPU destination
// ─────────────────────────────────────────────────────────────────────────────

func TestUploadPartCopy_MPU_PlaintextSource_EncryptedDest(t *testing.T) {
	f := setupUPCMPUFixture(t)
	dstKey := "test11-mpu-plain.bin"

	got := encryptedMPUCopy(t, f.mpuSDK, f.dstBucket, dstKey,
		f.srcBucket+"/"+f.srcPlaintextKey, nil)

	assert.Equal(t, f.srcData, got, "gateway GET must return original plaintext")

	// At-rest: raw backend bytes must not contain first 1 KiB of plaintext.
	atRestIsEncrypted(t, f.rawClient, f.dstBucket, dstKey, f.srcData)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 12: chunked source → encrypted MPU destination with range
// ─────────────────────────────────────────────────────────────────────────────

func TestUploadPartCopy_MPU_ChunkedSource_EncryptedDest_WithRange(t *testing.T) {
	f := setupUPCMPUFixture(t)

	// Mid-chunk range: bytes 10000–200000 (crosses two 64 KiB chunks).
	const rangeStart, rangeEnd = 10000, 200000
	rangeHdr := fmt.Sprintf("bytes=%d-%d", rangeStart, rangeEnd)
	dstKey := "test12-mpu-chunked.bin"

	got := encryptedMPUCopy(t, f.mpuSDK, f.dstBucket, dstKey,
		f.srcBucket+"/"+f.srcChunkedKey, &rangeHdr)

	want := f.srcData[rangeStart : rangeEnd+1]
	assert.Equal(t, want, got, "ranged encrypted-MPU copy must return correct slice")

	// At-rest ciphertext must differ from plaintext slice.
	atRestIsEncrypted(t, f.rawClient, f.dstBucket, dstKey, want)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 13: legacy source → encrypted MPU destination; assert legacy cap metric
// ─────────────────────────────────────────────────────────────────────────────

func TestUploadPartCopy_MPU_LegacySource_EncryptedDest(t *testing.T) {
	f := setupUPCMPUFixture(t)

	before := fetchMetricValue(t, f.gateway.URL,
		"gateway_upload_part_copy_legacy_fallback_total")

	dstKey := "test13-mpu-legacy.bin"
	got := encryptedMPUCopy(t, f.mpuSDK, f.dstBucket, dstKey,
		f.srcBucket+"/"+f.srcLegacyKey, nil)

	assert.Equal(t, f.srcData, got, "legacy → encrypted MPU round trip")
	atRestIsEncrypted(t, f.rawClient, f.dstBucket, dstKey, f.srcData)

	after := fetchMetricValue(t, f.gateway.URL,
		"gateway_upload_part_copy_legacy_fallback_total")
	assert.Greater(t, after, before, "legacy_fallback_total must increment")
}
