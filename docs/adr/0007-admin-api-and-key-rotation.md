# 7. Admin API and Key Rotation (Metadata-Only Cutover)

- **Date**: 2026-04-17
- **Status**: Accepted
- **Authors**: V0.6 Crypto / Config team

## Context

The S3 encryption gateway uses envelope encryption: each object gets a unique
Data Encryption Key (DEK) wrapped by a Key Encryption Key (KEK) managed by a
`KeyManager` adapter (in-memory, Cosmian KMIP, or future HSM). When the
operator wants to rotate the KEK — e.g. after a quarterly rotation policy
triggers, or a key is suspected compromised — the system must perform a
controlled cutover so that:

1. **New objects** use the new KEK version.
2. **Existing objects** remain decryptable; their DEKs were wrapped with the
   old KEK, and the old version is never deleted.
3. **In-flight wraps** that started before the cutover complete safely under
   the old version; no half-written envelopes.

This is a *metadata-only* rotation: no object ciphertext is rewritten. The
per-object DEK is still unique and random; only the wrapping key changes.

## Decision

### Separate Admin Listener

Admin routes are served on a **dedicated TCP listener** (default
`127.0.0.1:8081`), isolated from the S3 data-plane. This prevents
accidental exposure of admin endpoints to unauthenticated S3 clients and
allows independent TLS/firewall policy.

### Bearer Token Authentication

Admin endpoints require `Authorization: Bearer <token>` with constant-time
comparison (`crypto/subtle.ConstantTimeCompare`). Tokens are sourced from
a file (`admin.auth.token_file`, recommended) or inline (`admin.auth.token`,
dev only with `ADMIN_ALLOW_INLINE_TOKEN=1` override).

### Extension Interface (`RotatableKeyManager`)

A new **optional** Go interface extends `KeyManager`:

```go
type RotatableKeyManager interface {
    KeyManager
    PrepareRotation(ctx context.Context, target *int) (RotationPlan, error)
    PromoteActiveVersion(ctx context.Context, plan RotationPlan) error
}
```

Adapters opt in via compile-time interface satisfaction. The HSM stub
intentionally does not implement it (returns 501 on rotation endpoints).

### Drain-and-Cutover State Machine

Rotation follows a five-phase state machine:

```
idle → draining → ready_for_cutover → committing → committed
                                    ↗               ↘
                              (force)               aborted
```

- **draining**: a background poller watches an atomic in-flight wrap counter
  (`BeginWrap` / `EndWrap` around every `WrapKey` call). When the counter
  reaches zero (or a grace deadline elapses), the state advances to
  `ready_for_cutover`.
- **commit**: calls `PromoteActiveVersion` on the adapter, atomically
  advancing the wrapping key version. A `force` flag allows bypassing the
  drain.

### Endpoints

| Method | Path                        | Purpose          |
|--------|-----------------------------|------------------|
| POST   | `/admin/kms/rotate/start`   | Begin drain      |
| GET    | `/admin/kms/rotate/status`  | Poll snapshot    |
| POST   | `/admin/kms/rotate/commit`  | Promote version  |
| POST   | `/admin/kms/rotate/abort`   | Cancel rotation  |

## Alternatives Considered

1. **SigV4-reserved admin key**: Reuse the S3 data-plane with a special AWS
   credential that maps to "admin". Rejected: mixes security domains; any
   request-routing bug could expose admin operations.

2. **SIGHUP-triggered rotation**: Send a Unix signal to rotate. Rejected:
   no drain phase, no status polling, no audit trail, incompatible with
   Kubernetes where SIGHUP is unreliable.

3. **Bulk re-encryption**: Rewrite every object's DEK with the new KEK.
   Rejected: O(n) in object count, requires read+write auth on every bucket,
   and risks data loss if interrupted. Metadata-only rotation is O(1).

## Consequences

- Operators gain a safe, auditable rotation workflow.
- The `RotatableKeyManager` interface is backward-compatible; existing
  adapters that don't implement it simply return 501.
- Future HSM adapters can implement `RotatableKeyManager` when the PKCS#11
  backend supports versioned keys.
- The in-flight counter adds zero-allocation overhead to the WrapKey hot path
  (atomic int64 increment/decrement).

## References

- V0.6-CFG-1 plan: `docs/plans/V0.6-CFG-1-plan.md`
- Key rotation runbook: `docs/KEY_ROTATION_RUNBOOK.md`
- Conformance suite extension: `internal/crypto/keymanager_conformance.go`
