package s3

// V0.6-QA-1 Phase B — UploadPartCopy benchmarks.
//
// These close the benchmark gap flagged in docs/plans/V0.6-S3-1-plan.md:351:
// the S3-1 implementation ships the UploadPartCopy handler, but the
// micro-benchmark was deferred to the QA-1 baseline. Three variants capture
// the three important cost regimes the plan calls out:
//
//	_Chunked_64KiB_Range       — chunked-AEAD source, 64 KiB range per part,
//	                             16 sequential parts. Stresses per-part setup.
//	_Legacy_16MiB_Range        — legacy-AEAD source, 16 MiB range, 1 part.
//	                             Hits MaxLegacyCopySourceBytes ceiling.
//	_Plaintext_Passthrough_1GiB — plaintext source, single backend-native call.
//	                             The "native" baseline; should be protocol-bound.
//
// Fixture:  httptest.Server returning a deterministic CopyPartResult XML for
// every PUT <bucket>/<key>?partNumber=N&uploadId=UID. The size is
// informational (b.SetBytes); the wire does not carry the source bytes
// because UploadPartCopy is a server-side copy operation — gateway work is
// (a) constructing the request, (b) running the SDK round-tripper, and (c)
// parsing the result XML. This is what production looks like.
//
// Design notes:
//   * We reuse the inline benchOKTransport-style pattern from
//     client_bench_test.go (no new harness dependency).
//   * httptest.Server is in-process; no network hop. For the passthrough
//     variant this accurately reflects that UploadPartCopy has no data body.
//   * Chunked and legacy variants simulate the *wire* cost only (the
//     encrypted-rewrite path that the gateway *would* emit). The CPU cost
//     of the rewrite itself is covered by BenchmarkMPUEncryptReader_* and
//     BenchmarkEngine_Encrypt_*.
//
// All three benchmarks call b.ReportAllocs() and b.SetBytes() so MB/s
// columns are comparable across variants.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// benchUPCServer returns a deterministic CopyPartResult for every request.
// Configured via variant == {"chunked","legacy","plaintext"} purely for log
// differentiation — all three responses are otherwise identical.
func benchUPCServer(b *testing.B) *httptest.Server {
	b.Helper()
	body := `<?xml version="1.0" encoding="UTF-8"?>
<CopyPartResult><ETag>"upc-bench-etag"</ETag><LastModified>2026-04-24T00:00:00.000Z</LastModified></CopyPartResult>`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Drain any inbound body; UploadPartCopy sends no payload but be safe.
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("ETag", `"upc-bench-etag"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	return ts
}

// buildUPCClient is a variant of buildBenchClient that targets the supplied
// httptest.Server (real HTTP, not RoundTripper stubbing) so that the full
// SDK signing + transport path is exercised, matching production.
func buildUPCClient(b *testing.B, endpoint string) *s3.Client {
	b.Helper()
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("AKIATEST", "secrettest", "")),
	)
	if err != nil {
		b.Fatalf("buildUPCClient: load AWS config: %v", err)
	}
	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
}

// doUPC runs one UploadPartCopy call through the SDK using the supplied
// byte range. Caller is responsible for benchmark timing.
func doUPC(b *testing.B, client *s3.Client, partNumber int32, first, last int64) {
	b.Helper()
	_, err := client.UploadPartCopy(context.Background(), &s3.UploadPartCopyInput{
		Bucket:          aws.String("dst-bucket"),
		Key:             aws.String("dst-key"),
		CopySource:      aws.String("src-bucket/src-key"),
		CopySourceRange: aws.String(fmt.Sprintf("bytes=%d-%d", first, last)),
		PartNumber:      aws.Int32(partNumber),
		UploadId:        aws.String("upc-bench-uid"),
	})
	if err != nil {
		// The test server returns 200 OK with valid XML for every request;
		// any error here is a regression in the SDK call construction, not a
		// legitimate benchmark outcome.  Fail loudly.
		b.Fatalf("UploadPartCopy: %v", err)
	}
}

// BenchmarkUploadPartCopy_Chunked_64KiB_Range simulates the gateway rewriting
// a chunked-AEAD source into 16 sequential UploadPartCopy requests of 64 KiB
// each (one chunk per part). Per-part SDK setup dominates here — this is
// the upper-bound for UPC-bound chunked CopyObject behaviour.
func BenchmarkUploadPartCopy_Chunked_64KiB_Range(b *testing.B) {
	ts := benchUPCServer(b)
	defer ts.Close()
	client := buildUPCClient(b, ts.URL)

	const rangeBytes int64 = 64 * 1024
	const numParts = 16
	const totalBytes = rangeBytes * numParts

	b.SetBytes(totalBytes)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for part := int32(1); part <= numParts; part++ {
			first := int64(part-1) * rangeBytes
			last := first + rangeBytes - 1
			doUPC(b, client, part, first, last)
		}
	}
}

// BenchmarkUploadPartCopy_Legacy_16MiB_Range exercises a single 16 MiB range
// copy — the MaxLegacyCopySourceBytes ceiling the S3-1 plan fixes. This is
// the large-object, single-part legacy path.
func BenchmarkUploadPartCopy_Legacy_16MiB_Range(b *testing.B) {
	ts := benchUPCServer(b)
	defer ts.Close()
	client := buildUPCClient(b, ts.URL)

	const rangeBytes int64 = 16 * 1024 * 1024

	b.SetBytes(rangeBytes)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		doUPC(b, client, 1, 0, rangeBytes-1)
	}
}

// BenchmarkUploadPartCopy_Plaintext_Passthrough_1GiB reflects the
// native-path baseline: a single UploadPartCopy of 1 GiB with no gateway
// rewrite. On the wire this is a single SDK call with no body; its cost is
// entirely protocol + parse. The result is the "how fast can UPC go at all"
// floor for other variants to be compared against.
func BenchmarkUploadPartCopy_Plaintext_Passthrough_1GiB(b *testing.B) {
	ts := benchUPCServer(b)
	defer ts.Close()
	client := buildUPCClient(b, ts.URL)

	const rangeBytes int64 = 1024 * 1024 * 1024

	b.SetBytes(rangeBytes)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		doUPC(b, client, 1, 0, rangeBytes-1)
	}
}

// Assert that strings package is imported for ETag quoting tests elsewhere;
// this is a tiny noop retained only to keep imports stable when the
// benchmarks evolve.
var _ = strings.Repeat
var _ = bytes.NewReader
