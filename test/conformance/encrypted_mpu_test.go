//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"testing"

	"github.com/kenneth/s3-encryption-gateway/test/harness"
	"github.com/kenneth/s3-encryption-gateway/test/provider"
)

// testEncryptedMPURoundTrip verifies that the encrypted multipart upload path
// (ADR-0009 / V0.6-SEC-3) produces a correctly decryptable object.
//
// The test starts a dedicated Valkey container, configures the gateway with
// EncryptMultipartUploads=true for the test bucket, uploads a 2-part object
// (each part ≥ 5 MiB as required by S3), completes the upload, then reads the
// object back via the same gateway and asserts byte-perfect round-trip.
//
// This exercises the full encrypted MPU code path:
//   - CreateMultipartUpload  → DEK generation, IV-prefix derivation, Valkey state creation
//   - UploadPart             → per-part chunk encryption, Valkey part record append
//   - CompleteMultipartUpload → manifest assembly, finalization
//   - GetObject              → encrypted manifest read, DEK unwrap, decryption
func testEncryptedMPURoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	// Start a Valkey container for MPU state.
	vk := provider.StartValkey(ctx, t)

	// Start the gateway with encrypted MPU enabled for this bucket.
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
		harness.WithEncryptedMPUForBucket(inst.Bucket),
	)

	key := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key, uploadID) })

	// S3 requires every part except the last to be ≥ 5 MiB.
	part1Data := bytes.Repeat([]byte("A"), 5*1024*1024)
	part2Data := bytes.Repeat([]byte("B"), 5*1024*1024)
	part3Data := []byte("final-tail") // last part may be < 5 MiB

	etag1 := uploadPart(t, gw, inst.Bucket, key, uploadID, 1, part1Data)
	etag2 := uploadPart(t, gw, inst.Bucket, key, uploadID, 2, part2Data)
	etag3 := uploadPart(t, gw, inst.Bucket, key, uploadID, 3, part3Data)

	completeMultipartUpload(t, gw, inst.Bucket, key, uploadID, []mpuPart{
		{1, etag1},
		{2, etag2},
		{3, etag3},
	})

	// Read back the assembled object — the gateway must decrypt all parts and
	// re-assemble the plaintext in order.
	want := append(append(append([]byte(nil), part1Data...), part2Data...), part3Data...)
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, want) {
		t.Errorf("encrypted MPU round-trip: got %d bytes, want %d bytes", len(got), len(want))
	}
}

// testEncryptedMPUAbortCleansState verifies that AbortMultipartUpload on an
// encrypted upload removes the Valkey state entry (no orphaned DEK material).
func testEncryptedMPUAbortCleansState(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	vk := provider.StartValkey(ctx, t)
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
		harness.WithEncryptedMPUForBucket(inst.Bucket),
	)

	key := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key)

	part1Data := bytes.Repeat([]byte("X"), 5*1024*1024)
	uploadPart(t, gw, inst.Bucket, key, uploadID, 1, part1Data)

	// Abort — this must clean up Valkey state.
	abortMultipartUpload(t, gw, inst.Bucket, key, uploadID)

	// The object must not exist.
	resp, err := gw.HTTPClient().Get(objectURL(gw, inst.Bucket, key))
	if err != nil {
		t.Fatalf("GET after encrypted MPU abort: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("GET after encrypted MPU abort: status %d, want 404", resp.StatusCode)
	}
}
