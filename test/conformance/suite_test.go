//go:build conformance

// Package conformance is the tier-2 multi-provider test suite.
//
// Build tag: conformance (never runs under default `go test ./...`).
//
// Run via:
//
//	make test-conformance              # all registered providers
//	make test-conformance-minio        # MinIO only (PR gate)
//	make test-conformance-local        # local providers (MinIO + Garage + RustFS)
//	make test-conformance-external     # external providers with credentials
//
// The suite is provider-agnostic: each testXxx function takes
// (t *testing.T, inst provider.Instance) and zero-branches on provider name.
// Capability bits drive t.Skipf when a backend does not support the feature
// under test.
package conformance

import (
	"context"
	"testing"

	"github.com/kenneth/s3-encryption-gateway/test/provider"
)

// TestConformance runs every conformance test case against every registered
// provider. Providers execute concurrently; test cases within a provider
// execute serially (safe to promote to parallel once the suite is stable —
// see open question §4 in the plan).
func TestConformance(t *testing.T) {
	providers := provider.All()
	if len(providers) == 0 {
		t.Skip("No providers registered; set provider credentials or ensure Docker is available")
	}

	for _, p := range providers {
		p := p
		t.Run(p.Name(), func(t *testing.T) {
			t.Parallel() // Different providers run concurrently.
			ctx := context.Background()
			inst := p.Start(ctx, t)

			cases := []struct {
				name string
				cap  provider.Capabilities
				fn   func(*testing.T, provider.Instance)
			}{
				// Core object operations — run on every provider.
				{"PutGet", 0, testPutGet},
				{"PutGet_LargeObject", 0, testPutGet_Large},
				{"HeadObject", 0, testHeadObject},
				{"ListObjects", 0, testListObjects},
				{"DeleteObject", 0, testDeleteObject},
				{"DeleteObjects", provider.CapBatchDelete, testDeleteObjects},
				{"CopyObject", 0, testCopyObject},
				{"RangedRead", 0, testRangedRead},
				{"RangedRead_CrossChunk", 0, testRangedRead_CrossChunk},

				// Encryption round-trips (chunked + legacy AEAD).
				{"Chunked_RoundTrip", 0, testChunkedRoundTrip},
				{"Chunked_RangedRead", 0, testChunkedRangedRead},
				{"Legacy_RoundTrip", 0, testLegacyRoundTrip},

				// Multipart operations.
				{"Multipart_Basic", provider.CapMultipartUpload, testMultipartBasic},
				{"Multipart_Abort", provider.CapMultipartUpload, testMultipartAbort},
				{"Multipart_ListParts", provider.CapMultipartUpload, testMultipartListParts},

				// UploadPartCopy.
				{"UploadPartCopy_Full", provider.CapMultipartCopy, testUPC_Full},
				{"UploadPartCopy_Range", provider.CapMultipartCopy, testUPC_Range},
				{"UploadPartCopy_Plaintext", provider.CapMultipartCopy, testUPC_Plaintext},
				{"UploadPartCopy_Legacy", provider.CapMultipartCopy, testUPC_Legacy},
				{"UploadPartCopy_Mixed", provider.CapMultipartCopy, testUPC_Mixed},
				{"UploadPartCopy_AbortMidway", provider.CapMultipartCopy, testUPC_AbortMidway},
				{"UploadPartCopy_CrossBucket", provider.CapMultipartCopy, testUPC_CrossBucket},

			// Object tagging.
			// Tagging_Passthrough tests the x-amz-tagging header on PutObject
			// (inline tagging). Backends that only support ?tagging subresource
			// (e.g. Backblaze B2) skip this via CapInlinePutTagging.
			{"Tagging_Passthrough", provider.CapInlinePutTagging, testTaggingPassthrough},
			{"Tagging_GetPut", provider.CapObjectTagging, testTaggingGetPut},

				// Presigned URLs.
				{"Presigned_Get", provider.CapPresignedURL, testPresignedGet},
				{"Presigned_Put", provider.CapPresignedURL, testPresignedPut},

			// Key rotation — dual-read window, fail-closed, and metrics.
			{"Rotation_DualRead", 0, testRotationDualRead},
			{"Rotation_OldKeyUnreadable", 0, testRotationOldKeyUnreadableAfterRemoval},
			{"Rotation_Metric", 0, testRotationMetric},

				// Object Lock.
				{"ObjectLock_Retention", provider.CapObjectLock, testObjectLockRetention},
				{"ObjectLock_LegalHold", provider.CapObjectLock, testObjectLockLegalHold},
				{"ObjectLock_BypassRefused", provider.CapObjectLock, testObjectLockBypassRefused},

				// Metadata round-trip (catches cipher: authentication failed bugs).
				{"Metadata_RoundTrip", 0, testMetadataRoundTrip},

			// Concurrent operations.
			{"Concurrent_PutGet", 0, testConcurrentPutGet},

		// Encrypted multipart uploads (ADR-0009 / V0.6-SEC-3).
		// Requires Docker for a Valkey container (state store).
		{"EncryptedMPU_RoundTrip", provider.CapEncryptedMPU, testEncryptedMPURoundTrip},
		{"EncryptedMPU_AtRest", provider.CapEncryptedMPU, testEncryptedMPU_AtRest},
		{"EncryptedMPU_AbortCleansState", provider.CapEncryptedMPU, testEncryptedMPUAbortCleansState},

			// In-process load tests (range concurrency + multipart throughput).
			// Only run against local providers (MinIO, Garage) where per-request
			// latency is low enough for meaningful QPS assertions.
			{"Load_RangeRead", provider.CapLoadTest, testRangeLoad},
			{"Load_Multipart", provider.CapLoadTest | provider.CapMultipartUpload, testMultipartLoad},

			// Chaos tests — in-process ToxicServer, no real S3 backend used.
			// Gated on CapLoadTest so they only run on local providers (once
			// per provider is sufficient; the backend is a fake anyway).
			{"Chaos_Throttling", provider.CapLoadTest, testChaosThrottling},
			{"Chaos_Backend500", provider.CapLoadTest, testChaosBackend500},
			{"Chaos_NetworkTimeout", provider.CapLoadTest, testChaosNetworkTimeout},
		}

			for _, tc := range cases {
				tc := tc
				t.Run(tc.name, func(t *testing.T) {
					if tc.cap != 0 && p.Capabilities()&tc.cap == 0 {
						t.Skipf("%s does not advertise capability %s",
							p.Name(), tc.cap)
					}
					tc.fn(t, inst)
				})
			}
		})
	}
}
