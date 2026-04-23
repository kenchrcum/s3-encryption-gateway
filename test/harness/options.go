// Package harness provides a unified gateway launcher for conformance tests.
// One Gateway is started per test via StartGateway; all configuration is
// supplied via functional Option values so tests compose only what they need.
package harness

import (
	"net/http"

	"github.com/kenneth/s3-encryption-gateway/internal/audit"
	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/kenneth/s3-encryption-gateway/internal/mpu"
)

// options accumulates gateway configuration requested by Option functions.
type options struct {
	encryptionPassword  string
	policyManager       *config.PolicyManager
	keyManager          crypto.KeyManager
	mpuStore            mpu.StateStore
	auditLogger         audit.Logger
	encryptedMPU        bool
	valkeyAddr          string
	// encryptedMPUBucket is a glob pattern for which encrypted MPU is enabled.
	// When set the harness auto-creates a PolicyManager with
	// EncryptMultipartUploads=true for that pattern (unless policyManager is
	// already set by the caller).
	encryptedMPUBucket  string
	headObjectOverride  func(bucket, key string) *int64
	compressionEnabled  bool
	compressionAlgo     string
	logLevel            string
	extraConfig         func(*config.Config)
	// backendTransport, when non-nil, replaces the HTTP transport used by the
	// gateway's S3 backend client.  Use this in chaos / retry tests to inject
	// faults at the gateway→backend layer without an external proxy.
	// See WithBackendTransport and FaultyRoundTripper.
	backendTransport    http.RoundTripper
}

// Option is a functional option for StartGateway.
type Option func(*options)

// WithEncryptionPassword sets the gateway's encryption password.
// Defaults to "test-encryption-password-123456" if not set.
func WithEncryptionPassword(pw string) Option {
	return func(o *options) { o.encryptionPassword = pw }
}

// WithPolicyManager wires a per-bucket policy manager into the gateway.
func WithPolicyManager(pm *config.PolicyManager) Option {
	return func(o *options) { o.policyManager = pm }
}

// WithKeyManager wires a KeyManager (for MPU DEK wrap/unwrap) into the gateway.
func WithKeyManager(km crypto.KeyManager) Option {
	return func(o *options) { o.keyManager = km }
}

// WithMPUStateStore wires a Valkey/miniredis state store into the gateway
// for encrypted multipart uploads.
func WithMPUStateStore(store mpu.StateStore) Option {
	return func(o *options) { o.mpuStore = store }
}

// WithAuditLogger wires an audit logger into the gateway.
func WithAuditLogger(al audit.Logger) Option {
	return func(o *options) { o.auditLogger = al }
}

// WithEncryptedMPU enables the encrypted-multipart-upload feature.
// Requires WithMPUStateStore or WithValkeyAddr to also be set so the
// gateway has a Valkey/miniredis state store.
func WithEncryptedMPU(enabled bool) Option {
	return func(o *options) { o.encryptedMPU = enabled }
}

// WithValkeyAddr sets the Valkey/Redis address (host:port) for the MPU state
// store. The harness constructs a ValkeyStateStore from this address.
// Mutually exclusive with WithMPUStateStore; the latter takes precedence.
func WithValkeyAddr(addr string) Option {
	return func(o *options) { o.valkeyAddr = addr }
}

// WithEncryptedMPUForBucket enables the encrypted multipart upload feature for
// the given bucket glob pattern. The harness creates a PolicyManager with
// EncryptMultipartUploads=true and a password-derived KeyManager (unless the
// caller already supplied WithKeyManager). Also requires WithValkeyAddr or
// WithMPUStateStore so the gateway has a state store.
func WithEncryptedMPUForBucket(bucketGlob string) Option {
	return func(o *options) { o.encryptedMPUBucket = bucketGlob }
}

// WithHeadObjectOverride wires a hook that overrides Content-Length returned
// by HeadObject for specific (bucket, key) pairs. Use this to simulate
// objects larger than 5 GiB without uploading real data.
// fn must return nil to leave Content-Length unmodified.
func WithHeadObjectOverride(fn func(bucket, key string) *int64) Option {
	return func(o *options) { o.headObjectOverride = fn }
}

// WithCompression enables compression with the given algorithm
// (e.g. "gzip", "zstd"). An empty algorithm uses the default.
func WithCompression(algorithm string) Option {
	return func(o *options) {
		o.compressionEnabled = true
		o.compressionAlgo = algorithm
	}
}

// WithLogLevel sets the gateway logger level (default "error" in tests).
func WithLogLevel(level string) Option {
	return func(o *options) { o.logLevel = level }
}

// WithConfigMutator supplies a function that can make arbitrary mutations to
// the config.Config struct after all other options have been applied. Use
// sparingly; prefer typed options for discoverable configuration.
func WithConfigMutator(fn func(*config.Config)) Option {
	return func(o *options) { o.extraConfig = fn }
}

// WithBackendTransport replaces the HTTP transport used by the gateway's S3
// backend client.  When set, every backend request the gateway makes passes
// through rt before hitting the real (or fake) backend.
//
// Primary use: fault injection in retry / chaos conformance tests.  For
// example, wrap a real provider's transport with FaultyRoundTripper to inject
// transient errors at a controlled rate while still using a real MinIO backend
// for correctness assertions.
//
// Production code must never call this; it is for tests only.
func WithBackendTransport(rt http.RoundTripper) Option {
	return func(o *options) { o.backendTransport = rt }
}
