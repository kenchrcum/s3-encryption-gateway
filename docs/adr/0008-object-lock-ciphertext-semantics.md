# ADR 0008: Object Lock Ciphertext Semantics

## Status
Accepted — 2026-04-18 (V0.6-S3-2)

## Context
When an object is written through the encryption gateway with S3 Object
Lock fields set (`x-amz-object-lock-mode`,
`x-amz-object-lock-retain-until-date`,
`x-amz-object-lock-legal-hold`), the gateway encrypts the plaintext and
forwards the lock fields to the backend on the resulting `PutObject`,
`CopyObject`, or `CompleteMultipartUpload` request. The **ciphertext
blob** is what the backend stores and therefore what the backend locks.

The gateway is a stateless proxy: it does not maintain its own WORM
store. All retention and legal-hold enforcement is delegated to the
backend (AWS S3, MinIO, Ceph RGW, Wasabi, …). The gateway's
contribution is routing the subresource endpoints
(PutObjectRetention, PutObjectLegalHold,
PutObjectLockConfiguration and their Get counterparts) and surfacing
backend lock state on GET / HEAD responses.

This ciphertext-locking model interacts non-trivially with key rotation
and with the caller's mental model of "retention".

## Decision
1. **Locks apply to ciphertext.** The bytes persisted by the backend
   — the ciphertext blob produced by the gateway's
   envelope-encryption pipeline — are what the Object Lock protects.
   The gateway cannot lock plaintext; plaintext is ephemeral and
   never hits storage.

2. **Key-rotation interaction is documented and observable.** Objects
   locked in `COMPLIANCE` mode cannot be rewritten by anyone, including
   the key-rotation worker, until the retention period expires. The
   worker is required to:
   - detect the backend refusal (S3 returns `AccessDenied` with a code
     indicating retention),
   - skip the object (do **not** retry as a general failure),
   - emit one structured log entry per skip,
   - increment the `gateway_rotation_skipped_locked_total` Prometheus
     counter.

   Governance-mode objects are in principle rewritable with
   `x-amz-bypass-governance-retention`, but that header is refused by
   the gateway until V0.6-CFG-1 provides admin authorization; the
   rotation worker therefore skips governance-mode objects as well
   under v0.6.

3. **Readable-data durability is a separate guarantee.** Backend
   retention guarantees *byte durability* of the ciphertext; it does
   **not** guarantee that the data is still *readable*. If the KEK used
   to wrap a locked object's data-encryption key is retired from the
   available set before the lock expires, the locked bytes become an
   unrecoverable ciphertext blob. Operators must align KEK retention
   with the maximum Object Lock retention window in use.

4. **Provider support is non-uniform.** The gateway reports backend
   capability gaps as `501 NotImplemented` rather than silently
   accepting the request. The authoritative provider-support matrix
   lives in `docs/S3_API_IMPLEMENTATION.md` and is mirrored here for
   ADR stability:

   | Provider | Retention | Legal Hold | Bucket Config |
   |---|---|---|---|
   | AWS S3 | yes | yes | yes |
   | MinIO >= RELEASE.2021-01-30 (bucket created `--with-lock`) | yes | yes | yes |
   | Ceph RGW >= Pacific (feature-flagged) | yes | yes | yes |
   | Wasabi (Immutable Storage) | yes | yes | yes |
   | Backblaze B2 S3-compat | partial | partial | partial |
   | Hetzner Object Storage | partial | partial | partial |
   | DigitalOcean Spaces | no | no | no |
   | Cloudflare R2 | no | no | no |
   | Garage | no | no | no |

5. **`x-amz-bypass-governance-retention` is fail-closed.** Every
   gateway path that S3 would honour the header on — PutObjectRetention,
   DeleteObject, DeleteObjects — refuses a truthy value
   (case-insensitive) with `403 AccessDenied` and an audit event
   (`reason=admin_authorization_not_implemented`). Silent drop is
   unacceptable. V0.6-CFG-1 will replace the unconditional refusal
   with an admin-gated decision that also consults the
   `PolicyConfig.DisallowLockBypass` per-bucket opt-out introduced
   (but not yet consumed) by this work item.

## Consequences
- Operators must configure KMS / KEK retention to meet or exceed the
  maximum Object Lock retention window in use for their buckets.
- Key-rotation campaigns against buckets with locked content will
  leave residue of KEK versions that cannot be retired until the
  last locked object referencing them expires. Monitor
  `gateway_rotation_skipped_locked_total` to quantify.
- Operators who need to reduce a governance-mode retention before
  V0.6-CFG-1 lands must issue the call directly against the backend;
  the gateway refuses the bypass header.
- Clients querying lock state through the gateway (`GET` / `HEAD`
  `x-amz-object-lock-*` response headers) receive the backend-
  reported state. If the backend silently degrades (e.g. MinIO with
  `--without-lock` on bucket create), the gateway cannot compensate.

## Related Work
- V0.6-S3-2 — this change.
- V0.6-CFG-1 — admin primitive for bypass.
- ADR 0007 — Admin API and Key Rotation (home of the admin primitive
  this ADR defers to).
- ADR 0003 — KMS implementation scope for v0.5 (rotation workflow
  background).
- `docs/KEY_ROTATION_RUNBOOK.md` — operator guide documenting the
  locked-object skip behaviour.

## Open Questions / Future Work
- **Rotation anchoring.** A design wherein the KEK version used for a
  locked object is held in escrow with matching retention, preventing
  accidental KEK retirement. Out of scope for v0.6; flagged as a
  v1.0 candidate.
- **Plaintext-manifest locking.** A much larger design change that
  would let the gateway reject writes to locked *logical* objects
  independent of ciphertext identity. Not investigated here.
