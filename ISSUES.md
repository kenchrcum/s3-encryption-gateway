# S3 Encryption Gateway ? Findings, Bugs, and Roadmap (2025-11-01)

## Summary
Deep project analysis identified several correctness bugs (notably Range on encrypted objects, header ordering, and multipart encryption), security hardening items (AAD, allowed algorithms policy, key rotation metadata), and performance/operability improvements (streaming I/O, metrics cardinality, path-style config). This file tracks actionable issues and a prioritized roadmap.

---

## P0 ? Critical correctness bugs (fix first)

- Range on encrypted objects applied at backend (incorrect)
  - Problem: Range header is forwarded to S3 (partial ciphertext), then we decrypt and re-range plaintext. AEAD decryption of partial ciphertext is invalid and may fail or be unsafe.
  - Impact: Broken/undefined behavior for Range GETs on encrypted objects.
  - Fix:
    - Do not forward Range to backend for encrypted objects; fetch full object, decrypt, then apply Range on plaintext.
    - Longer-term: Implement segmented encryption format to allow server-side partial fetches safely.
  - Affected: `internal/api/handlers.go`, `internal/s3/client.go`, `internal/crypto/*`

- Response headers set after WriteHeader
  - Problem: In GET, headers from decrypted metadata are set after calling `WriteHeader`, so many headers are dropped.
  - Fix: Set headers before any `WriteHeader`/write calls. Ensure Content-Length/Content-Range are consistent.
  - Affected: `internal/api/handlers.go`

- Multipart encryption is not decryptable post-complete
  - Problem: Each part is encrypted independently; per-object salt/IV and algorithm metadata aren?t persisted at object level in a way S3 returns after completion. Completed object lacks required metadata to decrypt.
  - Options:
    - Short-term: Disable multipart upload endpoints for encrypted objects or transparently fall back to single PUT for supported sizes.
    - Mid-term: Define a segmented format with a manifest (nonce/key derivation/segment size) and store manifest in object metadata or prefixed header.
  - Affected: `internal/api/handlers.go`, `internal/s3/client.go`, `internal/crypto/*`

- CopyObject returns placeholder ETag
  - Problem: Uses a hardcoded ETag instead of backend-provided value.
  - Fix: Use backend CopyObject response ETag; ensure integrity of metadata.
  - Affected: `internal/api/handlers.go`

---

## P1 ? Security hardening

- Allowed algorithms policy (AES-256-GCM default; ChaCha20-Poly1305 supported)
  - Problem: Documentation previously implied AES-only.
  - Fix: Validate configured algorithms are within the approved set {AES-256-GCM, ChaCha20-Poly1305}; default to AES-256-GCM. Update docs to reflect support.
  - Affected: `internal/config/config.go` (validation), docs

- Bind critical metadata via AEAD AAD
  - Problem: AEAD additional data is nil; encryption metadata and selected headers can be tampered without detection.
  - Fix: Include algorithm, salt, key version, and critical headers (e.g., Content-Type, original size) as AAD in Seal/Open.
  - Affected: `internal/crypto/engine.go`, `internal/crypto/decrypt_reader.go`

- Key rotation metadata and decryption strategy
  - Problem: `KeyManager` exists but key version not written to object metadata; engine derives from a single password.
  - Fix: Write `x-amz-meta-encryption-key-version` on encrypt; on decrypt, try active key then older versions from `KeyManager` until success.
  - Affected: `internal/crypto/engine.go`, `internal/crypto/keymanager.go`, `internal/api/handlers.go`

- Secrets handling
  - Improve: Avoid long-lived `string` for passwords; prefer ephemeral derived key material, zeroed promptly. Consider KMS integration for secret storage.

---

## P1 ? Performance and scalability

- Streaming encrypt/decrypt (eliminate full buffering)
  - Problem: Multiple `io.ReadAll` reads across engine, compression, handlers, and S3 client cause large memory and latency overheads.
  - Fix:
    - Implement streaming `EncryptReader`/`DecryptReader` (io.Pipe + chunked AEAD).
    - Update S3 client to stream uploads/downloads (no full buffering).
  - Affected: `internal/crypto/*`, `internal/s3/client.go`, `internal/api/handlers.go`, `internal/crypto/compression.go`

- Metrics label cardinality
  - Problem: Using full `path` label (includes object keys) explodes cardinality.
  - Fix: Replace `path` with route pattern or bucket-only label; optionally add sampled exemplars.
  - Affected: `internal/metrics/metrics.go`, call sites

---

## P2 ? Compatibility and operability

- Path-style addressing configuration
  - Problem: Path-style is toggled only when `UseSSL == false`; many providers need path-style with TLS.
  - Fix: Add `use_path_style` to backend config and honor it regardless of TLS.
  - Affected: `internal/s3/client.go`, `internal/config/config.go`, `config.yaml.example`

- Metadata preservation breadth
  - Problem: `isStandardMetadata` whitelists few headers; may drop `Content-Encoding`, `Content-Language`, `Content-Disposition`, `Cache-Control` variants, `Content-MD5`, etc.
  - Fix: Expand whitelist or switch to pass-through of all non-encryption `x-amz-meta-*` plus a broader standard header set.
  - Affected: `internal/api/handlers.go`

- Compression policy polish
  - Improve: Avoid compressing already-compressed types (zip, gzip, images, video); ensure interactions with `Content-Encoding` are documented/set.
  - Affected: `internal/crypto/compression.go`

---

## Testing additions

- End-to-end tests
  - Range GET on encrypted objects (post-decrypt range correctness).
  - Multipart upload/download (until disabled or after segmented format) to ensure decryptability.
  - Key rotation: encrypt with older key version, decrypt after rotation.
  - Compression on/off by content type and size thresholds.
  - Metadata AAD tamper detection (when AAD added).

- Property tests
  - AEAD invariants: decrypt(encrypt(x)) == x; any tamper => fail.

---

## Proposed roadmap

- P0 (immediate)
  - Stop forwarding Range for encrypted objects; apply after decrypt.
  - Fix header ordering in GET path; set all headers before `WriteHeader`/body.
  - Disable multipart upload for encrypted objects (temporary) or guard behind config flag with clear warning.
  - Use backend ETag in CopyObject responses.

- P1 (next)
  - Add `MetaKeyVersion` on encrypt; on decrypt, try all versions from `KeyManager`.
  - Introduce AAD covering critical metadata.
  - Reduce metrics label cardinality.
  - Add `use_path_style` config.

- P2 (later)
  - Implement streaming AEAD and update S3 client/handlers to stream.
  - Design and implement segmented encryption format supporting Range and multipart.
  - Broaden metadata preservation and refine compression policy.

---

## Impacted areas (non-exhaustive)

- API: `internal/api/handlers.go`
- Crypto: `internal/crypto/engine.go`, `internal/crypto/decrypt_reader.go`, `internal/crypto/compression.go`, `internal/crypto/algorithms.go`, `internal/crypto/keymanager.go`
- S3 client: `internal/s3/client.go`
- Metrics: `internal/metrics/metrics.go`
- Config: `internal/config/config.go`, `config.yaml.example`


