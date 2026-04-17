# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — v0.6

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
