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
