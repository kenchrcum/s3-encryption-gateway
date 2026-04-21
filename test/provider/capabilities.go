package provider

import "fmt"

// Capabilities is a bitmask of features a Provider supports. Tests call
// t.Skipf when the tested capability bit is absent from the provider's bitmap.
type Capabilities uint64

const (
	// CapObjectLock indicates the backend supports Object Lock / WORM retention.
	CapObjectLock Capabilities = 1 << iota
	// CapObjectTagging indicates support for PutObjectTagging / GetObjectTagging.
	CapObjectTagging
	// CapMultipartUpload indicates support for the S3 multipart upload API.
	CapMultipartUpload
	// CapMultipartCopy indicates support for UploadPartCopy.
	CapMultipartCopy
	// CapVersioning indicates support for bucket versioning.
	CapVersioning
	// CapServerSideEncryption indicates native server-side encryption
	// (SSE-S3 / SSE-KMS). The gateway itself always encrypts client-side;
	// this flag is for backends that also support SSE on top.
	CapServerSideEncryption
	// CapPresignedURL indicates support for pre-signed GET / PUT URLs.
	CapPresignedURL
	// CapConditionalWrites indicates support for If-None-Match / If-Match on PUT.
	CapConditionalWrites
	// CapBatchDelete indicates support for the DeleteObjects (multi-delete)
	// XML batch shape.
	CapBatchDelete
	// CapKMSIntegration indicates that the Cosmian KMS integration works with
	// this provider (i.e. the provider is reachable from the KMS container and
	// vice-versa in the test network).
	CapKMSIntegration
	// CapInlinePutTagging indicates the backend accepts x-amz-tagging as an
	// inline header on PutObject. Backends that only support tagging via the
	// ?tagging subresource (e.g. Backblaze B2) do NOT set this bit; they still
	// set CapObjectTagging to indicate ?tagging subresource support.
	CapInlinePutTagging
	// CapEncryptedMPU indicates that the conformance test for encrypted
	// multipart uploads should run against this provider. All providers that
	// support multipart uploads should set this; the test itself starts a
	// Valkey container for state storage (Docker required).
	CapEncryptedMPU
	// CapLoadTest indicates that the provider is suitable for in-process load
	// tests (range and multipart throughput/concurrency checks). Providers with
	// high per-request latency (external/cloud) skip these to keep CI fast.
	CapLoadTest
)

// capNames maps each bit to a human-readable label for Stringer output.
var capNames = []struct {
	bit  Capabilities
	name string
}{
	{CapObjectLock, "ObjectLock"},
	{CapObjectTagging, "ObjectTagging"},
	{CapMultipartUpload, "MultipartUpload"},
	{CapMultipartCopy, "MultipartCopy"},
	{CapVersioning, "Versioning"},
	{CapServerSideEncryption, "SSE"},
	{CapPresignedURL, "PresignedURL"},
	{CapConditionalWrites, "ConditionalWrites"},
	{CapBatchDelete, "BatchDelete"},
	{CapKMSIntegration, "KMSIntegration"},
	{CapInlinePutTagging, "InlinePutTagging"},
	{CapEncryptedMPU, "EncryptedMPU"},
	{CapLoadTest, "LoadTest"},
}

// String returns a human-readable description of the capabilities bitmap.
func (c Capabilities) String() string {
	if c == 0 {
		return "none"
	}
	var out string
	for _, cn := range capNames {
		if c&cn.bit != 0 {
			if out != "" {
				out += "|"
			}
			out += cn.name
		}
	}
	if out == "" {
		return fmt.Sprintf("unknown(0x%x)", uint64(c))
	}
	return out
}
