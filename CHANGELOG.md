# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — v0.6

### Operations & Helm

- **Blue/green and canary deployment recipes** (V0.6-OPS-1): the Helm chart
  now ships production-safe progressive-delivery topologies for zero-downtime
  upgrades of the S3 Encryption Gateway.

  - **New chart value `track`** (default `""`): labels pods for selector-based
    traffic routing. Set to `"blue"`, `"green"`, `"stable"`, or `"canary"`.
    Single-release deployments see no change (backward compatible; empty track
    emits no label).

  - **New `ingress.traefik.*` values**: first-class Traefik v3 CRD support.
    - `ingress.traefik.enabled: true` renders a `traefik.io/v1alpha1`
      `IngressRoute` as the replacement for the standard `networking.k8s.io/v1`
      Ingress. Mutually exclusive with `ingress.enabled` (chart enforces this).
    - `ingress.traefik.weighted.enabled: true` renders a `kind: Weighted`
      `TraefikService` + companion `IngressRoute` for the canary traffic-split
      topology. Weights must sum to 100 (chart enforces this).

  - **New `terminationGracePeriodSeconds` and `lifecycle` values**: expose
    pod lifecycle knobs for safe connection draining during traffic flips.
    Default `terminationGracePeriodSeconds: 30` preserves existing behaviour.

  - **Template-time guard-rails** (`templates/validate.yaml`):
    - `track` + `valkey.enabled: true` → render-time error (shared Valkey
      required for MPU state continuity across traffic flips).
    - `track` without a Valkey address → render-time error.
    - `ingress.enabled` + `ingress.traefik.enabled` both true → render-time error.
    - `ingress.traefik.weighted.enabled` without `ingress.traefik.enabled` → error.
    - Weighted services not summing to 100 → render-time error.

  - **New chart templates**: `templates/ingressroute.yaml`,
    `templates/traefikservice.yaml` (both opt-in; emit zero output by default).

  - **Per-track Prometheus relabeling**: `ServiceMonitor` and `PodMonitor`
    templates now emit a `track` relabel rule when `track` is set, enabling
    per-track PromQL queries and Grafana dashboard filtering.

  - **Example values files** (`helm/s3-encryption-gateway/examples/`):
    `values-blue.yaml`, `values-green.yaml`, `values-canary-stable.yaml`,
    `values-canary-canary.yaml`, `values-traefik-single.yaml`.

  - **Raw manifest examples** (`docs/examples/`):
    - `bluegreen/service.yaml` — operator-owned shared Service for the
      selector-flip pattern.
    - `bluegreen/external-valkey.yaml` — minimal shared Valkey StatefulSet.
    - `bluegreen/cutover.sh` — cutover and rollback script.
    - `canary/traefikservice.yaml`, `canary/ingressroute.yaml` — operator-owned
      Traefik resources for the weighted canary split.
    - `canary/promote.sh` — progressive weight promotion (5 → 25 → 50 → 100).
    - `canary/rollback.sh` — emergency rollback script.
    - `gateway-api/httproute.yaml` — portable Gateway API `HTTPRoute` equivalent
      (documentation appendix; not a chart template in v0.6).

  - **Operator runbook**: `docs/OPS_DEPLOYMENT.md` is the single authoritative
    source for blue/green and canary procedures, including the stateful
    invariants (shared Valkey, key-version parity, draining semantics),
    per-track observability, troubleshooting guide, Gateway API appendix,
    and Argo Rollouts / Flagger optional overlay recipe.

  - **CI**: `.github/workflows/helm-test.yml` extended with progressive-delivery
    render checks and guard-rail smoke tests.

  - See `docs/plans/V0.6-OPS-1-plan.md` for full design rationale.

### Observability

- **Admin pprof profiling endpoints** (V0.6-OBS-1): production-safe runtime
  profiling is now available at `/admin/debug/pprof/*` on the **admin
  listener** when `admin.profiling.enabled: true`.

  - **Disabled by default.** Enabling requires `admin.enabled: true`;
    on non-loopback addresses also requires `admin.tls.enabled: true`.

  - **Security-inheriting.** All 11 pprof endpoints (index, cmdline,
    profile, symbol, trace, heap, goroutine, allocs, block, mutex,
    threadcreate) reuse the existing admin bearer-token auth, rate
    limiter, and TLS — no new auth surface.

  - **Semaphore-bounded.** `/profile` and `/trace` are bounded by
    `max_concurrent_profiles` (default 2) and `max_profile_seconds`
    (default 60); excess requests return `429 Retry-After: 1`.

  - **Block/mutex profiling knobs.** `block_rate` and `mutex_fraction`
    (both default 0/off) are passed to
    `runtime.SetBlockProfileRate` / `SetMutexProfileFraction` at startup.

  - **Audited.** Every fetch emits a `pprof_fetch` audit event with
    endpoint, duration, and HTTP status.

  - **New Prometheus metrics:** `s3_gateway_admin_pprof_requests_total
    {endpoint, outcome}` (bounded cardinality: 11 × 4 = 44 label
    combinations) and `gateway_admin_profiling_enabled` gauge.

  - **Dockerfile `STRIP_SYMBOLS` build-arg.** Both `Dockerfile` and
    `Dockerfile.fips` now accept `--build-arg STRIP_SYMBOLS=false` to
    produce a symbolicated binary for profiling sessions without
    permanently removing symbols from production images. Use
    `make profile-image` as a convenience shortcut.

  - **Operator recipes** added to `docs/OBSERVABILITY.md §"Runtime
    Profiling"` (CPU flamegraph, heap snapshot, goroutine-leak workflow).

  - **Admin API reference** updated in `docs/ADMIN_API.md` with the
    route table and response code semantics.

  - **New config keys** (all optional, default `false`/`0`):
    `admin.profiling.enabled`, `.block_rate`, `.mutex_fraction`,
    `.max_concurrent_profiles` (default 2), `.max_profile_seconds`
    (default 60). See `config.yaml.example` for the annotated stanza.

  - **ADR 0011** filed: `docs/adr/0011-admin-profiling-endpoints.md`.

  - See `docs/plans/V0.6-OBS-1-plan.md` for full design rationale.

### Performance

- **Configurable S3 backend retry policy** (V0.6-PERF-2):
  Replaced the SDK-default retryer with a gateway-specific `aws.RetryerV2`
  implementation (`internal/s3/retry.go`) backed by the new
  `backend.retry.*` configuration stanza:

  - **Operator-configurable knobs** (all optional, defaults match SDK
    behaviour): `mode` (`standard` | `adaptive` | `off`),
    `max_attempts` (1–10, default 3), `initial_backoff` (default 100 ms),
    `max_backoff` (default 20 s), `jitter`
    (`full` | `decorrelated` | `equal` | `none`, default `full`),
    `per_operation` override map, `safe_copy_object` gate.

  - **Idempotency safeguards**: `CompleteMultipartUpload` now defaults to
    `max_attempts: 1` (non-idempotent post-commit); retrying a successful
    Complete would return `NoSuchUpload` and confuse the caller. Callers
    that need retry should do so at the application layer.

  - **HTTP 429 classified as retryable** for all backends (the SDK's
    default classifier only retries 429 if the response body contains a
    known throttle error code, which Wasabi and Hetzner do not include).

  - **Crypto errors are hard non-retryable** (`ErrInvalidEnvelope`,
    `ErrUnwrapFailed`, `ErrKeyNotFound`, `ErrProviderUnavailable`) — no
    auto-retry on tamper-detected objects.

  - **Context-aware sleep** — request cancellation interrupts a sleeping
    retry without goroutine leaks.

  - **`Retry-After` header honoured** for HTTP 429/503 responses.

  - **Three new Prometheus metrics**:
    `s3_backend_retries_total{operation, reason, mode}`,
    `s3_backend_attempts_per_request{operation}`,
    `s3_backend_retry_give_ups_total{operation, final_reason}`, and
    `s3_backend_retry_backoff_seconds` histogram.

  - **Audit event** `backend.retry_give_up` emitted on data-plane write
    give-ups (not on read-path give-ups to avoid noise).

  - **`adaptive` mode** available for contended backends; wraps the SDK's
    `retry.AdaptiveMode` token bucket.

  - **`off` mode** disables retries entirely for debug and
    conformance-test isolation.

  - See `docs/adr/0010-backend-retry-policy.md` and
    `config.yaml.example` for the full knob reference.

- **Zero-copy streaming on hot data paths** (V0.6-PERF-1): eliminated
  full-object in-memory buffers on the most allocation-heavy paths:

  - **`handleGetObject` optimised range path**: the `io.ReadAll` at the
    partial-content response stage is replaced with `io.CopyBuffer`
    directly to the response writer using a pooled 64 KiB buffer.
    `Content-Length` is computed from the already-known plaintext range,
    so no intermediate `[]byte` slice is needed.

  - **`handleCopyObject`**: the double-allocation
    (`ReadAll(decryptedReader)` → `Encrypt(bytes.NewReader(decryptedData))`
    → `ReadAll(encryptedReader)`) is reduced to a single allocation
    inside the engine. `decryptedReader` is now passed directly to
    `Encrypt`, eliminating the intermediate `decryptedData []byte`. A
    legacy-source size cap (`Server.MaxLegacyCopySourceBytes`, default
    256 MiB) is now also enforced on `handleCopyObject` (previously
    only on `UploadPartCopy`).

  - **`handleUploadPart`**: `io.ReadAll(r.Body)` and
    `io.ReadAll(encReader)` are replaced with a pooled
    `SeekableBody` wrapper (`internal/s3/seekable_body.go`) that
    satisfies the AWS SDK V2 SigV4 seekable-body contract while capping
    heap per part at `Server.MaxPartBuffer` (new config knob, default
    **64 MiB**). Parts above the cap are refused with HTTP 413 before
    any backend write occurs.

  - **Compression engine** (`internal/crypto/compression.go`):
    `Compress` now returns a streaming `io.Pipe` reader instead of
    buffering the full compressed output; `Decompress` returns a
    `*gzip.Reader` wrapping the plaintext directly. The post-hoc
    "skip if compressed ≥ original" size check is removed in favour of
    the `ShouldCompress` pre-filter (size + content-type), consistent
    with nginx / Envoy precedent. ADR 0006 addendum documents the
    behaviour change.

  - **Engine compression branch** (`internal/crypto/engine.go`): the
    `bytes.NewReader(compressedData)` intermediate re-wrap is eliminated;
    the compression pipe reader flows directly into the AEAD boundary.
    The engine Decrypt path also drops a redundant `io.ReadAll →
    bytes.NewReader` round-trip.

  - **Streaming MPU part encrypt reader**
    (`internal/crypto/mpu_encrypter.go`, Phase G): `NewMPUPartEncryptReader`
    now returns a true streaming `io.Reader` (`*mpuEncryptReader`) that
    encrypts one 64 KiB AEAD chunk per `Read` call. Peak heap per part
    is O(chunkSize + tagSize) ≈ 65 KiB regardless of part size, down
    from O(plaintext + ciphertext). The DEK is defensively copied by
    the reader so that callers may safely zero their DEK slice
    immediately after the constructor returns (fixing a latent bug
    where `defer zeroBytes(dek)` would corrupt IVs under the previous
    streaming design). IV derivation remains deterministic — retries
    produce byte-identical ciphertext.

### Added

- **Unified multi-provider conformance test suite** (V0.6-QA-4):
  Introduced `test/provider/`, `test/harness/`, and
  `test/conformance/` packages implementing a three-tier test taxonomy
  (Unit / Conformance / Soak+Load+Chaos). The new `Provider` interface
  and Testcontainers-Go-backed MinIO (`minio/minio:RELEASE.2024-11-07T00-52-20Z`),
  Garage (`dxflrs/garage:v2.3.0`), and Valkey (`valkey/valkey:8.0-alpine`)
  implementations replace the four inconsistent test harness variants
  that existed previously. 32 provider-agnostic conformance tests
  cover PutGet, Head, List, Delete, BatchDelete, CopyObject, ranged
  reads (including cross-chunk boundaries), chunked and legacy AEAD
  encryption, multipart upload (basic / abort / list-parts),
  UploadPartCopy (full / range / plaintext / legacy / mixed / abort /
  cross-bucket), object tagging, presigned URLs, key-rotation
  dual-read window, Object Lock retention / legal-hold / bypass-refused,
  metadata round-trip, and concurrent operations under `-race`.
  External S3 vendors (AWS, Wasabi, Backblaze B2, Hetzner) plug in
  via a one-file pattern and activate automatically when credentials
  are set. A mechanical `matrix_guard_test.go` AST check prevents
  provider-name literals from appearing in conformance test bodies;
  `scripts/test-isolation.sh` prevents regression to `docker-compose`
  / hard-coded ports / binary backend invocations.

  New `make` targets: `test-conformance`, `test-conformance-local`,
  `test-conformance-minio`, `test-conformance-external`,
  `test-isolation-check`. `make test-comprehensive` now runs
  tier-1 + local conformance + isolation check without requiring
  `docker-compose up`. See `docs/TESTING.md`.

  **Phase-1 hotfix**: `StartSharedMinIOServerForProvider` in
  `test/minio.go` now creates the bucket before returning, fixing the
  root cause of the `TestProvider_Compatibility` /
  `TestGateway_ProviderIntegration` failures in `make test-comprehensive`
  step 3.

### Fixed

- **User metadata was silently dropped on PUT / CopyObject / MPU**
  (uncovered by V0.6-QA-4). Four sites in `internal/api/handlers.go`
  (`handlePutObject`, `filterS3Metadata`, `handleCreateMultipartUpload`,
  `handleCopyObject`) compared `k[:11] == "x-amz-meta-"` against keys
  from `r.Header`. Go canonicalises HTTP headers to `X-Amz-Meta-Foo`
  on parse, so the case-sensitive comparison never matched and all
  `x-amz-meta-*` headers were discarded. Replaced with
  `strings.HasPrefix(strings.ToLower(k), "x-amz-meta-")` and
  lowercase the map key for downstream consistency.

- **`DeleteObjects` failed against MinIO and older S3-compatible
  backends** (uncovered by V0.6-QA-4). MinIO
  (pre-`RELEASE.2024-11-07T00-52-20Z` era) and many other backends
  only validate the legacy `Content-MD5` integrity header; AWS SDK
  v2 migrated to `x-amz-checksum-*` and no longer auto-computes
  `Content-MD5`. Added a smithy finalize-stage middleware in
  `internal/s3/client.go` that computes and sets `Content-MD5`
  from the serialised body when not already present. Idempotent
  against AWS (which also accepts the header).

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
