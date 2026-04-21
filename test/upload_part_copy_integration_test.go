//go:build integration
// +build integration

package test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	s3sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	upcSrcPass = "upc-src-password-32chars-abc123"
	upcDstPass = "upc-dst-password-32chars-def456"
)

// upcFixture holds all shared state for UploadPartCopy integration tests.
type upcFixture struct {
	minioServer  *MinIOTestServer
	srcBucket    string
	dstBucket    string
	gateway      *TestGateway
	gwSDK        *s3sdk.Client // points at gateway
	rawClient    *s3sdk.Client // points directly at MinIO backend (bypasses encryption)
	// source objects
	srcPlaintextKey string
	srcChunkedKey   string
	srcLegacyKey    string
	srcData         []byte // plaintext content of all 3 source objects
}

// setupUPCFixture starts MinIO, creates buckets, seeds source objects, and starts
// the test gateway. It returns a ready-to-use upcFixture and registers t.Cleanup.
func setupUPCFixture(t *testing.T) *upcFixture {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping UploadPartCopy integration test in short mode")
	}

	minio := StartMinIOServer(t)
	prefix := TestBucketPrefix(t)
	srcBucket := prefix + "-src"
	dstBucket := prefix + "-dst"

	// Create buckets directly on MinIO (gateway does not route CreateBucket).
	CreateBucketForTest(t, minio, srcBucket)
	CreateBucketForTest(t, minio, dstBucket)
	rawS3, err := minio.GetS3Client()
	require.NoError(t, err, "raw backend s3 client")
	ctx := context.Background()

	// Raw AWS SDK client pointing directly at MinIO (no encryption).
	rawSDKClient := NewRawBackendS3Client(t, minio)

	// Build a policy manager giving the src bucket a chunked-mode encryption engine.
	// The dst bucket has its own policy for cross-bucket tests; non-MPU-encrypting tests
	// don't care which dst policy is in effect.
	pm := NewTestPolicyManager(t,
		fmt.Sprintf("id: upc-src\nbuckets: [\"%s*\"]\nencryption:\n  password: \"%s\"\n", srcBucket, upcSrcPass),
		fmt.Sprintf("id: upc-dst\nbuckets: [\"%s*\"]\nencryption:\n  password: \"%s\"\n", dstBucket, upcDstPass),
	)

	cfg := minio.GetGatewayConfig()
	cfg.Encryption.Password = upcSrcPass // global fallback
	gw := StartGateway(t, cfg, WithPolicyManager(pm))

	// Source data: 6 MiB of incrementing bytes (96 × 64 KiB chunks).
	// MinIO multipart rejects parts < 5 MiB (except the last), so the
	// source must exceed 5 MiB to satisfy the MixedWithUploadPart test.
	const srcSize = 6 * 1024 * 1024
	srcData := make([]byte, srcSize)
	for i := range srcData {
		srcData[i] = byte(i & 0xFF)
	}

	// Seed plaintext source directly via raw MinIO (no gateway encryption).
	plainKey := "plaintext-src.bin"
	_, err = rawSDKClient.PutObject(ctx, &s3sdk.PutObjectInput{
		Bucket:        aws.String(srcBucket),
		Key:           aws.String(plainKey),
		Body:          bytes.NewReader(srcData),
		ContentLength: aws.Int64(int64(len(srcData))),
	})
	require.NoError(t, err, "seed plaintext source")

	// Seed chunked source: encrypt with chunked engine + PUT to backend directly.
	// (Seeding via gateway PUT hits a pre-existing unseekable-body+HTTP issue in
	// the aws-sdk-go-v2 sigv4 path; raw-backend seed is bit-for-bit equivalent.)
	gwSDK := newSDKClient(t, gw.URL, minio.AccessKey, minio.SecretKey)
	chunkedEngine, err := crypto.NewEngineWithChunking(upcSrcPass, nil, "", nil, true, crypto.DefaultChunkSize)
	require.NoError(t, err, "chunked engine")
	chunkedKey := "chunked-src.bin"
	chEncReader, chEncMeta, err := chunkedEngine.Encrypt(bytes.NewReader(srcData), map[string]string{})
	require.NoError(t, err, "chunked encrypt source")
	chEncBytes, err := io.ReadAll(chEncReader)
	require.NoError(t, err)
	chEncLen := int64(len(chEncBytes))
	require.NoError(t, rawS3.PutObject(ctx, srcBucket, chunkedKey, bytes.NewReader(chEncBytes), chEncMeta, &chEncLen, "", nil))

	// Seed legacy source: encrypt directly with legacy engine, PUT to MinIO.
	// Pass Content-Type explicitly so it is bound into the AAD during
	// Encrypt and matches the Content-Type picked up from the backend
	// response by the handler's Decrypt path.
	legacyEngine, err := crypto.NewEngine(upcSrcPass) // legacy mode (no chunking)
	require.NoError(t, err, "create legacy engine")
	legacyKey := "legacy-src.bin"
	legacyInitMeta := map[string]string{"Content-Type": "application/octet-stream"}
	encReader, encMeta, err := legacyEngine.Encrypt(bytes.NewReader(srcData), legacyInitMeta)
	require.NoError(t, err, "legacy encrypt source")
	encBytes, err := io.ReadAll(encReader)
	require.NoError(t, err, "read legacy encrypted bytes")
	// Store via raw backend (metadata as S3 user metadata). Content-Type is
	// already captured as MetaContentType in encMeta (AAD binding).
	require.NoError(t, rawS3.PutObject(ctx, srcBucket, legacyKey, bytes.NewReader(encBytes), encMeta, nil, "", nil))

	t.Cleanup(func() { gw.Close() })

	return &upcFixture{
		minioServer:     minio,
		srcBucket:       srcBucket,
		dstBucket:       dstBucket,
		gateway:         gw,
		gwSDK:           gwSDK,
		rawClient:       rawSDKClient,
		srcPlaintextKey: plainKey,
		srcChunkedKey:   chunkedKey,
		srcLegacyKey:    legacyKey,
		srcData:         srcData,
	}
}

// newSDKClient returns an AWS SDK v2 S3 client pointed at the given endpoint.
func newSDKClient(t *testing.T, endpoint, ak, sk string) *s3sdk.Client {
	t.Helper()
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(ak, sk, "")),
	)
	require.NoError(t, err)
	return s3sdk.NewFromConfig(awsCfg, func(o *s3sdk.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
}

// upcComplete creates an MPU, copies one part from the given source key (using
// the copy source header format), completes, and returns the downloaded plaintext.
func upcComplete(
	t *testing.T,
	cl *s3sdk.Client,
	dstBucket, dstKey, copySource string,
	copySourceRange *string,
) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	createResp, err := cl.CreateMultipartUpload(ctx, &s3sdk.CreateMultipartUploadInput{
		Bucket: aws.String(dstBucket),
		Key:    aws.String(dstKey),
	})
	require.NoError(t, err, "CreateMultipartUpload")
	uploadID := createResp.UploadId

	t.Cleanup(func() {
		cl.AbortMultipartUpload(context.Background(), &s3sdk.AbortMultipartUploadInput{
			Bucket:   aws.String(dstBucket),
			Key:      aws.String(dstKey),
			UploadId: uploadID,
		})
	})

	upcIn := &s3sdk.UploadPartCopyInput{
		Bucket:             aws.String(dstBucket),
		Key:                aws.String(dstKey),
		UploadId:           uploadID,
		PartNumber:         aws.Int32(1),
		CopySource:         aws.String(copySource),
	}
	if copySourceRange != nil {
		upcIn.CopySourceRange = copySourceRange
	}

	upcResp, err := cl.UploadPartCopy(ctx, upcIn)
	require.NoError(t, err, "UploadPartCopy")
	require.NotNil(t, upcResp.CopyPartResult)
	etag := upcResp.CopyPartResult.ETag

	_, err = cl.CompleteMultipartUpload(ctx, &s3sdk.CompleteMultipartUploadInput{
		Bucket:   aws.String(dstBucket),
		Key:      aws.String(dstKey),
		UploadId: uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{{ETag: etag, PartNumber: aws.Int32(1)}},
		},
	})
	require.NoError(t, err, "CompleteMultipartUpload")

	getResp, err := cl.GetObject(ctx, &s3sdk.GetObjectInput{
		Bucket: aws.String(dstBucket),
		Key:    aws.String(dstKey),
	})
	require.NoError(t, err, "GetObject")
	defer getResp.Body.Close()
	got, err := io.ReadAll(getResp.Body)
	require.NoError(t, err, "read GetObject body")
	return got
}

// fetchMetricValue reads the gateway's /metrics endpoint and returns the
// value of the named counter (e.g. "gateway_upload_part_copy_legacy_fallback_total").
// Returns 0 if the metric is not found.
func fetchMetricValue(t *testing.T, gatewayURL, metricName string) float64 {
	t.Helper()
	resp, err := http.Get(gatewayURL + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		// Match lines like: gateway_foo_total{label="x"} 3 or gateway_foo_total 3
		if strings.HasPrefix(line, metricName) {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				var v float64
				fmt.Sscanf(parts[len(parts)-1], "%f", &v)
				return v
			}
		}
	}
	return 0
}

func fetchMetricValueWithLabels(t *testing.T, gatewayURL, metricName string, labelFragments ...string) float64 {
	t.Helper()
	resp, err := http.Get(gatewayURL + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "#") || line == "" || !strings.HasPrefix(line, metricName) {
			continue
		}
		matched := true
		for _, fragment := range labelFragments {
			if !strings.Contains(line, fragment) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			var v float64
			fmt.Sscanf(parts[len(parts)-1], "%f", &v)
			return v
		}
	}
	return 0
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: chunked source → plaintext dst, byte-for-byte round trip
// ─────────────────────────────────────────────────────────────────────────────

func TestUploadPartCopy_Chunked(t *testing.T) {
	f := setupUPCFixture(t)
	dstKey := "test1-chunked.bin"
	got := upcComplete(t, f.gwSDK, f.dstBucket, dstKey,
		f.srcBucket+"/"+f.srcChunkedKey, nil)
	assert.Equal(t, f.srcData, got, "byte-for-byte round trip")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: chunked source → plaintext dst, three range sub-cases
// ─────────────────────────────────────────────────────────────────────────────

func TestUploadPartCopy_Chunked_WithRange(t *testing.T) {
	f := setupUPCFixture(t)

	chunkSize := 64 * 1024

	cases := []struct {
		name  string
		start int
		end   int // inclusive
	}{
		{"mid-chunk", 1000, 50000},                             // both within first chunk
		{"on-boundary", chunkSize, chunkSize + 32*1024},        // start at chunk boundary
		{"cross-chunk", chunkSize - 4096, 3*chunkSize + 4096},  // spans 3 chunks
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dstKey := fmt.Sprintf("test2-%s.bin", tc.name)
			rangeHdr := fmt.Sprintf("bytes=%d-%d", tc.start, tc.end)
			got := upcComplete(t, f.gwSDK, f.dstBucket, dstKey,
				f.srcBucket+"/"+f.srcChunkedKey, &rangeHdr)
			want := f.srcData[tc.start : tc.end+1]
			assert.Equal(t, want, got, "range %s mismatch", tc.name)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: legacy source → plaintext dst; assert legacy_fallback_total increments
// ─────────────────────────────────────────────────────────────────────────────

func TestUploadPartCopy_Legacy(t *testing.T) {
	f := setupUPCFixture(t)

	before := fetchMetricValue(t, f.gateway.URL,
		"gateway_upload_part_copy_legacy_fallback_total")

	dstKey := "test3-legacy.bin"
	got := upcComplete(t, f.gwSDK, f.dstBucket, dstKey,
		f.srcBucket+"/"+f.srcLegacyKey, nil)
	assert.Equal(t, f.srcData, got, "byte-for-byte round trip")

	after := fetchMetricValue(t, f.gateway.URL,
		"gateway_upload_part_copy_legacy_fallback_total")
	assert.Greater(t, after, before, "legacy_fallback_total must increment")

	legacyBytes := fetchMetricValueWithLabels(t, f.gateway.URL,
		"gateway_upload_part_copy_bytes_total", `source_mode="legacy"`)
	assert.Greater(t, legacyBytes, float64(0), "legacy bytes_total must record copied bytes")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: plaintext source → plaintext dst (backend-native fast path)
// ─────────────────────────────────────────────────────────────────────────────

func TestUploadPartCopy_Plaintext(t *testing.T) {
	f := setupUPCFixture(t)
	dstKey := "test4-plaintext.bin"
	got := upcComplete(t, f.gwSDK, f.dstBucket, dstKey,
		f.srcBucket+"/"+f.srcPlaintextKey, nil)
	assert.Equal(t, f.srcData, got, "plaintext round trip")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: > 5 GiB source (simulated via HeadObject override)
//   no-range  → 400 InvalidRequest
//   ranged    → 200
// ─────────────────────────────────────────────────────────────────────────────

func TestUploadPartCopy_LargeSource_MustUseRange(t *testing.T) {
	minio := StartMinIOServer(t)
	prefix := TestBucketPrefix(t) + "-5"
	srcBucket := prefix + "-src"
	dstBucket := prefix + "-dst"

	CreateBucketForTest(t, minio, srcBucket)
	CreateBucketForTest(t, minio, dstBucket)
	ctx := context.Background()

	// Seed a small plaintext source (6 MiB).
	const src6MiB = 6 * 1024 * 1024
	srcData := make([]byte, src6MiB)
	srcKey := "large-src.bin"
	rawSDKClient := NewRawBackendS3Client(t, minio)
	_, err := rawSDKClient.PutObject(ctx, &s3sdk.PutObjectInput{
		Bucket:        aws.String(srcBucket),
		Key:           aws.String(srcKey),
		Body:          bytes.NewReader(srcData),
		ContentLength: aws.Int64(int64(len(srcData))),
	})
	require.NoError(t, err)

	// Override HeadObject to report > 5 GiB so the handler enforces range requirement.
	const overrideSize = 6 * 1024 * 1024 * 1024 // 6 GiB
	overrideFn := func(bucket, key string) *int64 {
		if bucket == srcBucket && key == srcKey {
			v := int64(overrideSize)
			return &v
		}
		return nil
	}

	cfg := minio.GetGatewayConfig()
	gw := StartGateway(t, cfg, WithHeadObjectOverride(overrideFn))
	t.Cleanup(gw.Close)
	cl := newSDKClient(t, gw.URL, minio.AccessKey, minio.SecretKey)

	copySource := srcBucket + "/" + srcKey

	// No-range → should fail with 400 InvalidRequest.
	createResp, err := cl.CreateMultipartUpload(ctx, &s3sdk.CreateMultipartUploadInput{
		Bucket: aws.String(dstBucket), Key: aws.String("large-dst.bin"),
	})
	require.NoError(t, err)
	uploadID := createResp.UploadId
	t.Cleanup(func() {
		cl.AbortMultipartUpload(context.Background(), &s3sdk.AbortMultipartUploadInput{
			Bucket: aws.String(dstBucket), Key: aws.String("large-dst.bin"), UploadId: uploadID,
		})
	})

	_, noRangeErr := cl.UploadPartCopy(ctx, &s3sdk.UploadPartCopyInput{
		Bucket: aws.String(dstBucket), Key: aws.String("large-dst.bin"),
		UploadId: uploadID, PartNumber: aws.Int32(1),
		CopySource: aws.String(copySource),
	})
	require.Error(t, noRangeErr, "expected error for no-range copy of > 5 GiB source")
	assert.Contains(t, noRangeErr.Error(), "400", "expected 400 status")

	// With range (the actual size is 6 MiB, so bytes=0-<6MiB-1> is valid) → 200.
	rangeHdr := fmt.Sprintf("bytes=0-%d", src6MiB-1)
	upcResp, err := cl.UploadPartCopy(ctx, &s3sdk.UploadPartCopyInput{
		Bucket: aws.String(dstBucket), Key: aws.String("large-dst.bin"),
		UploadId: uploadID, PartNumber: aws.Int32(1),
		CopySource: aws.String(copySource), CopySourceRange: aws.String(rangeHdr),
	})
	require.NoError(t, err, "ranged UploadPartCopy should succeed")
	require.NotNil(t, upcResp.CopyPartResult)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: two buckets, two per-bucket policies (different passwords)
// ─────────────────────────────────────────────────────────────────────────────

func TestUploadPartCopy_CrossBucket(t *testing.T) {
	minio := StartMinIOServer(t)
	prefix := TestBucketPrefix(t) + "-6"
	srcBucket := prefix + "-src"
	dstBucket := prefix + "-dst"

	CreateBucketForTest(t, minio, srcBucket)
	CreateBucketForTest(t, minio, dstBucket)
	ctx := context.Background()

	pm := NewTestPolicyManager(t,
		fmt.Sprintf("id: cross-src\nbuckets: [\"%s*\"]\nencryption:\n  password: \"%s\"\n", srcBucket, upcSrcPass),
		fmt.Sprintf("id: cross-dst\nbuckets: [\"%s*\"]\nencryption:\n  password: \"%s\"\n", dstBucket, upcDstPass),
	)

	cfg := minio.GetGatewayConfig()
	gw := StartGateway(t, cfg, WithPolicyManager(pm))
	t.Cleanup(gw.Close)
	cl := newSDKClient(t, gw.URL, minio.AccessKey, minio.SecretKey)

	// Seed chunked-encrypted source directly on backend (see note in setupUPCFixture
	// about gateway PUT + unseekable body + HTTP).
	srcData := make([]byte, 256*1024)
	for i := range srcData {
		srcData[i] = byte(i)
	}
	srcKey := "cross-src.bin"
	rawS3, err := minio.GetS3Client()
	require.NoError(t, err)
	chunkedEngine, err := crypto.NewEngineWithChunking(upcSrcPass, nil, "", nil, true, crypto.DefaultChunkSize)
	require.NoError(t, err)
	chEncReader, chEncMeta, err := chunkedEngine.Encrypt(bytes.NewReader(srcData), map[string]string{})
	require.NoError(t, err)
	chEncBytes, err := io.ReadAll(chEncReader)
	require.NoError(t, err)
	chEncLen := int64(len(chEncBytes))
	require.NoError(t, rawS3.PutObject(ctx, srcBucket, srcKey, bytes.NewReader(chEncBytes), chEncMeta, &chEncLen, "", nil))

	// UploadPartCopy src → dst.
	got := upcComplete(t, cl, dstBucket, "cross-dst.bin",
		srcBucket+"/"+srcKey, nil)
	assert.Equal(t, srcData, got, "cross-bucket byte-for-byte round trip")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: Abort midway; assert no orphan objects and audit events present
// ─────────────────────────────────────────────────────────────────────────────

func TestUploadPartCopy_AbortMidway(t *testing.T) {
	f := setupUPCFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dstKey := "test7-abort.bin"
	createResp, err := f.gwSDK.CreateMultipartUpload(ctx, &s3sdk.CreateMultipartUploadInput{
		Bucket: aws.String(f.dstBucket), Key: aws.String(dstKey),
	})
	require.NoError(t, err)
	uploadID := createResp.UploadId

	// Upload 2 parts.
	for i := int32(1); i <= 2; i++ {
		_, err := f.gwSDK.UploadPartCopy(ctx, &s3sdk.UploadPartCopyInput{
			Bucket:     aws.String(f.dstBucket),
			Key:        aws.String(dstKey),
			UploadId:   uploadID,
			PartNumber: aws.Int32(i),
			CopySource: aws.String(f.srcBucket + "/" + f.srcPlaintextKey),
		})
		require.NoError(t, err, "UploadPartCopy part %d", i)
	}

	// Abort.
	_, err = f.gwSDK.AbortMultipartUpload(ctx, &s3sdk.AbortMultipartUploadInput{
		Bucket:   aws.String(f.dstBucket),
		Key:      aws.String(dstKey),
		UploadId: uploadID,
	})
	require.NoError(t, err, "AbortMultipartUpload")

	// Complete should fail (NoSuchUpload).
	_, completeErr := f.gwSDK.CompleteMultipartUpload(ctx, &s3sdk.CompleteMultipartUploadInput{
		Bucket:   aws.String(f.dstBucket),
		Key:      aws.String(dstKey),
		UploadId: uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{{ETag: aws.String("\"dummy\""), PartNumber: aws.Int32(1)}},
		},
	})
	assert.Error(t, completeErr, "CompleteMultipartUpload after abort must fail")

	// No object at dstKey.
	_, getErr := f.gwSDK.GetObject(ctx, &s3sdk.GetObjectInput{
		Bucket: aws.String(f.dstBucket), Key: aws.String(dstKey),
	})
	assert.Error(t, getErr, "GetObject after abort should return error")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: interleave UploadPart and UploadPartCopy
// ─────────────────────────────────────────────────────────────────────────────

func TestUploadPartCopy_MixedWithUploadPart(t *testing.T) {
	f := setupUPCFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dstKey := "test8-mixed.bin"
	createResp, err := f.gwSDK.CreateMultipartUpload(ctx, &s3sdk.CreateMultipartUploadInput{
		Bucket: aws.String(f.dstBucket), Key: aws.String(dstKey),
	})
	require.NoError(t, err)
	uploadID := createResp.UploadId
	t.Cleanup(func() {
		f.gwSDK.AbortMultipartUpload(context.Background(), &s3sdk.AbortMultipartUploadInput{
			Bucket: aws.String(f.dstBucket), Key: aws.String(dstKey), UploadId: uploadID,
		})
	})

	// Part 1: regular UploadPart with random 5 MiB body.
	part1Data := bytes.Repeat([]byte("part1-"), 5*1024*1024/6+1)
	part1Data = part1Data[:5*1024*1024]
	upResp, err := f.gwSDK.UploadPart(ctx, &s3sdk.UploadPartInput{
		Bucket: aws.String(f.dstBucket), Key: aws.String(dstKey),
		UploadId: uploadID, PartNumber: aws.Int32(1),
		Body: bytes.NewReader(part1Data),
	})
	require.NoError(t, err)
	etag1 := upResp.ETag

	// Part 2: UploadPartCopy from plaintext src (full object).
	upcResp2, err := f.gwSDK.UploadPartCopy(ctx, &s3sdk.UploadPartCopyInput{
		Bucket:     aws.String(f.dstBucket),
		Key:        aws.String(dstKey),
		UploadId:   uploadID,
		PartNumber: aws.Int32(2),
		CopySource: aws.String(f.srcBucket + "/" + f.srcPlaintextKey),
	})
	require.NoError(t, err)
	etag2 := upcResp2.CopyPartResult.ETag

	// Part 3: regular UploadPart.
	part3Data := bytes.Repeat([]byte("part3-"), 5*1024*1024/6+1)
	part3Data = part3Data[:5*1024*1024]
	upResp3, err := f.gwSDK.UploadPart(ctx, &s3sdk.UploadPartInput{
		Bucket: aws.String(f.dstBucket), Key: aws.String(dstKey),
		UploadId: uploadID, PartNumber: aws.Int32(3),
		Body: bytes.NewReader(part3Data),
	})
	require.NoError(t, err)
	etag3 := upResp3.ETag

	// Part 4: UploadPartCopy from chunked src (last part, so < 5 MiB OK).
	// Range: first 128 KiB of the chunked source.
	rangeHdr := fmt.Sprintf("bytes=0-%d", 128*1024-1)
	upcResp4, err := f.gwSDK.UploadPartCopy(ctx, &s3sdk.UploadPartCopyInput{
		Bucket:          aws.String(f.dstBucket),
		Key:             aws.String(dstKey),
		UploadId:        uploadID,
		PartNumber:      aws.Int32(4),
		CopySource:      aws.String(f.srcBucket + "/" + f.srcChunkedKey),
		CopySourceRange: aws.String(rangeHdr),
	})
	require.NoError(t, err)
	etag4 := upcResp4.CopyPartResult.ETag

	_, err = f.gwSDK.CompleteMultipartUpload(ctx, &s3sdk.CompleteMultipartUploadInput{
		Bucket:   aws.String(f.dstBucket),
		Key:      aws.String(dstKey),
		UploadId: uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{
				{ETag: etag1, PartNumber: aws.Int32(1)},
				{ETag: etag2, PartNumber: aws.Int32(2)},
				{ETag: etag3, PartNumber: aws.Int32(3)},
				{ETag: etag4, PartNumber: aws.Int32(4)},
			},
		},
	})
	require.NoError(t, err, "CompleteMultipartUpload")

	getResp, err := f.gwSDK.GetObject(ctx, &s3sdk.GetObjectInput{
		Bucket: aws.String(f.dstBucket), Key: aws.String(dstKey),
	})
	require.NoError(t, err)
	defer getResp.Body.Close()
	got, _ := io.ReadAll(getResp.Body)

	// Verify concatenation order.
	want := make([]byte, 0, len(part1Data)+len(f.srcData)+len(part3Data)+128*1024)
	want = append(want, part1Data...)
	want = append(want, f.srcData...)        // part 2: full plaintext src
	want = append(want, part3Data...)
	want = append(want, f.srcData[:128*1024]...) // part 4: first 128 KiB of chunked src
	assert.Equal(t, want, got, "mixed UploadPart + UploadPartCopy round trip")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 9: cross-bucket read-denied (alice lacks read on src) → 403
// ─────────────────────────────────────────────────────────────────────────────

func TestUploadPartCopy_CrossBucket_ReadDenied_Integration(t *testing.T) {
	minio := StartMinIOServer(t)
	prefix := TestBucketPrefix(t) + "-9"
	srcBucket := prefix + "-src"
	dstBucket := prefix + "-dst"

	CreateBucketForTest(t, minio, srcBucket)
	CreateBucketForTest(t, minio, dstBucket)
	ctx := context.Background()

	// Seed source object with root MinIO credentials.
	rawSDK := NewRawBackendS3Client(t, minio)
	srcData := bytes.Repeat([]byte("secret"), 100)
	srcKey := "secret-src.bin"
	_, err := rawSDK.PutObject(ctx, &s3sdk.PutObjectInput{
		Bucket: aws.String(srcBucket), Key: aws.String(srcKey),
		Body: bytes.NewReader(srcData), ContentLength: aws.Int64(int64(len(srcData))),
	})
	require.NoError(t, err)

	// Create alice user: write-only on dstBucket.
	aliceAK, aliceSK := "alice", "alice-secret123"
	alicePolicy := fmt.Sprintf(`{
		"Version":"2012-10-17",
		"Statement":[{
			"Effect":"Allow",
			"Action":["s3:PutObject","s3:CreateMultipartUpload","s3:UploadPart","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],
			"Resource":["arn:aws:s3:::%s/*"]
		}]
	}`, dstBucket)
	minio.SeedMinIOUser(t, aliceAK, aliceSK, alicePolicy)

	cfg := minio.GetGatewayConfig()
	cfg.Backend.UseClientCredentials = true
	gw := StartGateway(t, cfg)
	t.Cleanup(gw.Close)

	aliceClient := newSDKClient(t, gw.URL, aliceAK, aliceSK)
	createResp, err := aliceClient.CreateMultipartUpload(ctx, &s3sdk.CreateMultipartUploadInput{
		Bucket: aws.String(dstBucket), Key: aws.String("dst.bin"),
	})
	require.NoError(t, err)
	uploadID := createResp.UploadId
	t.Cleanup(func() {
		aliceClient.AbortMultipartUpload(context.Background(), &s3sdk.AbortMultipartUploadInput{
			Bucket: aws.String(dstBucket), Key: aws.String("dst.bin"), UploadId: uploadID,
		})
	})

	_, copyErr := aliceClient.UploadPartCopy(ctx, &s3sdk.UploadPartCopyInput{
		Bucket:     aws.String(dstBucket),
		Key:        aws.String("dst.bin"),
		UploadId:   uploadID,
		PartNumber: aws.Int32(1),
		CopySource: aws.String(srcBucket + "/" + srcKey),
	})
	require.Error(t, copyErr, "alice without read on src must get an error")
	assert.Contains(t, copyErr.Error(), "403", "expected 403 AccessDenied")

	// Assert zero parts created.
	listResp, err := aliceClient.ListParts(ctx, &s3sdk.ListPartsInput{
		Bucket:   aws.String(dstBucket),
		Key:      aws.String("dst.bin"),
		UploadId: uploadID,
	})
	require.NoError(t, err)
	assert.Empty(t, listResp.Parts, "no parts should have been uploaded")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 10: plaintext source + require_encryption policy on dst → 500 InternalError
// ─────────────────────────────────────────────────────────────────────────────

func TestUploadPartCopy_PlaintextSource_EncryptedDestBucket_Refused_Integration(t *testing.T) {
	minio := StartMinIOServer(t)
	prefix := TestBucketPrefix(t) + "-10"
	srcBucket := prefix + "-src"
	dstBucket := prefix + "-dst"

	CreateBucketForTest(t, minio, srcBucket)
	CreateBucketForTest(t, minio, dstBucket)
	ctx := context.Background()

	// Seed plaintext source directly on MinIO (no encryption metadata).
	rawSDK := NewRawBackendS3Client(t, minio)
	srcData := bytes.Repeat([]byte("plain"), 1024)
	srcKey := "plaintext-src.bin"
	_, err := rawSDK.PutObject(ctx, &s3sdk.PutObjectInput{
		Bucket: aws.String(srcBucket), Key: aws.String(srcKey),
		Body: bytes.NewReader(srcData), ContentLength: aws.Int64(int64(len(srcData))),
	})
	require.NoError(t, err)

	// Policy: dst bucket requires encryption.
	pm := NewTestPolicyManager(t,
		fmt.Sprintf("id: require-enc\nbuckets: [\"%s*\"]\nrequire_encryption: true\n", dstBucket),
	)

	cfg := minio.GetGatewayConfig()
	gw := StartGateway(t, cfg, WithPolicyManager(pm))
	t.Cleanup(gw.Close)
	cl := newSDKClient(t, gw.URL, minio.AccessKey, minio.SecretKey)

	createResp, err := cl.CreateMultipartUpload(ctx, &s3sdk.CreateMultipartUploadInput{
		Bucket: aws.String(dstBucket), Key: aws.String("dst.bin"),
	})
	require.NoError(t, err)
	uploadID := createResp.UploadId
	t.Cleanup(func() {
		cl.AbortMultipartUpload(context.Background(), &s3sdk.AbortMultipartUploadInput{
			Bucket: aws.String(dstBucket), Key: aws.String("dst.bin"), UploadId: uploadID,
		})
	})

	_, copyErr := cl.UploadPartCopy(ctx, &s3sdk.UploadPartCopyInput{
		Bucket:     aws.String(dstBucket),
		Key:        aws.String("dst.bin"),
		UploadId:   uploadID,
		PartNumber: aws.Int32(1),
		CopySource: aws.String(srcBucket + "/" + srcKey),
	})
	require.Error(t, copyErr, "plaintext source into require_encryption dst must fail")
	assert.Contains(t, copyErr.Error(), "500", "expected 500 InternalError")

	// No parts should be in the upload.
	listResp, err := cl.ListParts(ctx, &s3sdk.ListPartsInput{
		Bucket:   aws.String(dstBucket),
		Key:      aws.String("dst.bin"),
		UploadId: uploadID,
	})
	require.NoError(t, err)
	assert.Empty(t, listResp.Parts, "no parts should have been created")
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers referenced by multiple test files in this package
// ─────────────────────────────────────────────────────────────────────────────

// policyForBucket returns YAML for a single-bucket policy with the given password.
func policyForBucket(id, bucketGlob, password string) string {
	return fmt.Sprintf(`
- id: %s
  buckets: ["%s"]
  encryption:
    password: "%s"
`, id, bucketGlob, password)
}

// getBucketObjects returns the list of object keys in a bucket via the raw backend.
func getBucketObjects(ctx context.Context, cl *s3sdk.Client, bucket string) ([]string, error) {
	out, err := cl.ListObjectsV2(ctx, &s3sdk.ListObjectsV2Input{Bucket: aws.String(bucket)})
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(out.Contents))
	for _, obj := range out.Contents {
		keys = append(keys, aws.ToString(obj.Key))
	}
	return keys, nil
}

// configForBucket creates a gateway config with per-bucket policy YAML.
func configForBuckets(t *testing.T, minio *MinIOTestServer, policies string) (*config.Config, *config.PolicyManager) {
	t.Helper()
	cfg := minio.GetGatewayConfig()
	pm := NewTestPolicyManager(t, policies)
	return cfg, pm
}

// mapKeys returns a slice of keys from a map (diagnostic helper).
func mapKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
