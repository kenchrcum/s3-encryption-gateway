# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — v0.6

### Added

- **Object Lock / Retention / Legal Hold pass-through** (V0.6-S3-2):
  the six Object-Lock subresource endpoints are now routed
  (`PUT/GET /{bucket}/{key}?retention`, `?legal-hold`, and
  `PUT/GET /{bucket}?object-lock`) with strict XML validation, and
  the three `x-amz-object-lock-*` request headers are now forwarded
  end-to-end on `PutObject`, `CopyObject`, and
  `CompleteMultipartUpload`. `GetObject` / `HeadObject` responses
  surface the backend's `x-amz-object-lock-mode`,
  `x-amz-object-lock-retain-until-date`, and
  `x-amz-object-lock-legal-hold` headers. New ADR 0008 documents
  ciphertext-locking semantics and the interaction with key rotation.

### Changed

- **`x-amz-bypass-governance-retention` is now refused rather than
  silently dropped** (V0.6-S3-2). Any request carrying a truthy value
  for this header on `PutObjectRetention`, `DeleteObject`, or
  `DeleteObjects` now returns `403 AccessDenied` with an audit event
  (`reason=admin_authorization_not_implemented`). The previous
  behaviour (silent drop plus no retention effect) produced a false
  sense of compliance. Admin-gated forwarding lands with V0.6-CFG-1.

- **`Client` interface signatures** for `PutObject`, `CopyObject`,
  and `CompleteMultipartUpload` now take an optional
  `*ObjectLockInput`. Passing `nil` preserves the pre-change
  behaviour.

### Added

- **Admin API for Key Rotation** (V0.6-CFG-1): Separate admin listener with
  bearer-token authentication providing a safe drain-and-cutover key rotation
  workflow. Endpoints: `start`, `status`, `commit`, `abort`. Includes
  `RotatableKeyManager` extension interface for adapters that support runtime
  rotation, a `RotationState` state machine with atomic in-flight wrap
  tracking, and Prometheus metrics (`kms_active_key_version`,
  `kms_rotation_operations_total`, `kms_rotation_duration_seconds`,
  `kms_rotation_in_flight_wraps`, `gateway_admin_api_enabled`).
  Documentation: `docs/ADMIN_API.md`, ADR 0007.

- **Pluggable KeyManager Interface** (V0.6-SEC-1): Refactored to a pluggable
  `KeyManager` interface with adapters for in-memory, Cosmian KMIP, and HSM
  (build-tagged). Conformance test suite shared across all adapters.

- **FIPS-Compliant Crypto Profile** (V0.6-SEC-2): Optional FIPS build profile
  via `-tags=fips`; ChaCha20-Poly1305 excluded, AES-256-GCM only. PBKDF2
  migrated to stdlib. `Dockerfile.fips` and Helm FIPS overlay provided.

- **Multipart Copy Support** (V0.6-S3-1): `UploadPartCopy` handler with
  three source-class strategies (chunked, legacy, plaintext). 5 GiB per-call
  cap, legacy source OOM-defense cap, cross-bucket copy support.

- **Encrypted Multipart Uploads** (V0.6-SEC-3, ADR 0009): Closes the
  plaintext-at-rest gap for multipart uploads. Opt-in per bucket via
  `encrypt_multipart_uploads: true` in policy files. Architecture:
  - Per-upload 32-byte DEK wrapped by the configured `KeyManager`.
  - Per-part, per-chunk AEAD IVs derived via
    `HKDF-Expand(SHA-256, dek, salt=sha256(uploadId), info=ivPrefix||BE32(part)||BE32(chunk))`.
  - Finalization manifest stored as a companion object (`<key>.mpu-manifest`),
    with a metadata pointer on the final object.
  - `UploadPartCopy` into encrypted MPU destinations re-encrypts through
    the destination DEK schedule regardless of source class.
  - Range GETs supported: part-boundary arithmetic translates plaintext
    offsets to backend ciphertext offsets.
  - Tamper detection: AES-GCM tag failure on any chunk returns 500 + audit event.
  - **Requires Valkey** for in-flight state storage (`multipart_state.valkey.addr`).
    Startup fail-closed when Valkey is unreachable and any bucket policy enables
    encrypted MPU. Emergency escape hatch: `server.disable_multipart_uploads: true`.
  - New Prometheus metrics: `gateway_mpu_encrypted_total`,
    `gateway_mpu_parts_total`, `gateway_mpu_state_store_ops_total`,
    `gateway_mpu_state_store_latency_seconds`, `gateway_mpu_valkey_up`,
    `gateway_mpu_valkey_insecure`, `gateway_mpu_manifest_bytes`,
    `gateway_mpu_manifest_storage_total`.
  - New admin endpoints (gated by existing admin bearer auth):
    `POST /admin/mpu/abort/{uploadId}`, `GET /admin/mpu/list`.
  - New audit events: `mpu.create`, `mpu.part`, `mpu.complete`,
    `mpu.abort`, `mpu.tamper_detected`, `mpu.valkey_unavailable`.
  - `/readyz` endpoint extended with per-dependency checks (kms,
    valkey) returning a 503 with a JSON `checks` map when any
    configured dependency is unhealthy. K8s-convention aliases
    `/healthz`, `/readyz`, `/livez` added.
  - Helm chart: optional `valkey` subchart dependency
    (https://valkey.io/valkey-helm/, Apache-2.0, verified
    publisher); `VALKEY_ADDR` auto-wired when
    `valkey.enabled=true`. All Valkey config keys also accept env
    var overrides (`VALKEY_ADDR`, `VALKEY_TLS_ENABLED`, etc.).
  - FIPS-compliant: AES-256-GCM + HKDF-SHA256 primitives only; no
    ChaCha20 dependency. All SEC-3 code passes `go test -tags=fips
    -race` cleanly.
  - Default: `false` in v0.6 for soak. v0.7 flips default to `true`.

- **UploadPartCopy + Encrypted MPU Integration Test Suite** (V0.6-S3-3,
  plan: `docs/plans/V0.6-S3-3-plan.md`): 18 new integration tests closing
  every gap flagged during V0.6-S3-1 and V0.6-SEC-3 delivery:
  - Tests 1–10 (`TestUploadPartCopy_{Chunked,Chunked_WithRange,Legacy,Plaintext,
    LargeSource_MustUseRange,CrossBucket,AbortMidway,MixedWithUploadPart,
    CrossBucket_ReadDenied_Integration,PlaintextSource_EncryptedDestBucket_Refused_Integration}`)
    run against a real MinIO backend.
  - Tests 11–13 (`TestUploadPartCopy_MPU_{PlaintextSource_EncryptedDest,
    ChunkedSource_EncryptedDest_WithRange,LegacySource_EncryptedDest}`)
    close the Phase-E zero-coverage gap: UploadPartCopy into encrypted-MPU
    destinations is now exercised end-to-end against MinIO + Valkey.
  - Tests 14–17 (`TestEncryptedMPU_PasswordKeyManager_{SmallObject,Ranged_GET,
    AtRestCiphertext,AbortDeletesState}`) replace the env-gated
    `test/encrypted_mpu_test.go` smoke test with proper CI-runnable assertions
    including at-rest ciphertext checks and Valkey state-deletion verification.
  - Test 18 (`TestCosmianKMS_EncryptedMPU_RoundTrip`) adds Cosmian-wrapped
    DEK coverage to the encrypted-MPU code path.
  - Test harness extensions: `StartGateway` now accepts variadic
    `TestGatewayOption` values (`WithPolicyManager`, `WithKeyManager`,
    `WithMPUStateStore`, `WithAuditLogger`, `WithHeadObjectOverride`);
    all 16 existing gateway tests compile and pass unchanged.
  - New `test/mpu_fixtures.go` with `NewTestMPUStateStore`,
    `NewTestPasswordKeyManager`, `NewRawBackendS3Client`,
    `NewTestPolicyManager`, `EncryptedMPUPolicy`, `TestBucketPrefix`.
  - `MinIOTestServer.SeedMinIOUser` helper for multi-credential tests
    (skips cleanly if `mc` CLI is absent).

### Fixed

- **`UploadPartCopy` Phase-E silent data loss** (`internal/api/upload_part_copy.go`):
  when `mpuStateStore.AppendPart` fails during an UploadPartCopy into an
  encrypted-MPU destination, the handler previously logged a warning and
  returned 200 OK, leaving the encryption state store inconsistent. The fix
  aligns this path with `handlers.go:2730-2757`: the handler now logs at
  error level, records `RecordS3Error("AppendMPUPartState", "StateUnavailable")`,
  emits a `mpu.valkey_unavailable` audit event, and returns **503
  ServiceUnavailable** so the client retries. A duplicate backend part from
  a retry is discarded by `CompleteMultipartUpload`'s ETag-set reconciliation.
  New unit test: `TestUploadPartCopy_MPU_AppendPartFailure_Returns503`.
