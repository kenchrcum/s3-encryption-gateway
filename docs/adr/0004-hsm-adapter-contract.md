# ADR-0004 — HSM Adapter Contract (PKCS#11)

**Status:** Accepted (skeleton shipped in v0.6; functional implementation deferred to v1.0)
**Deciders:** Crypto team
**Date:** 2026-04-17

---

## Context

V0.6-SEC-1 introduces a pluggable `KeyManager` interface that lets alternative
KMS back-ends be wired into the encryption engine without touching core logic.
One planned back-end is a Hardware Security Module (HSM) accessed via the
industry-standard PKCS#11 API.

This ADR records the integration contract that a functional PKCS#11 adapter
MUST satisfy so that future implementers have a clear specification.

---

## Decision

### 1. Configuration surface

The HSM adapter is enabled with `provider: hsm` in `encryption.key_manager`.
It requires a dedicated `hsm:` subsection:

```yaml
encryption:
  key_manager:
    enabled: true
    provider: hsm
    hsm:
      module: /usr/lib/softhsm/libsofthsm2.so   # path to PKCS#11 shared library
      slot_id: 0                                  # PKCS#11 slot index
      pin_source: env:HSM_PIN                    # secret reference (see §3)
      wrapping_key_label: "master-wrap-key"      # CKA_LABEL of the AES wrapping key
      wrapping_mechanism: CKM_AES_KEY_WRAP       # PKCS#11 mechanism identifier
```

### 2. Build tags and cgo

The functional adapter requires cgo and a PKCS#11 header. It is gated by the
`hsm` build tag:

```
CGO_ENABLED=1 go build -tags hsm ./...
```

The default build (without `-tags hsm`) compiles `keymanager_hsm_stub.go`,
which returns `ErrProviderUnavailable` on every call with a clear message
pointing to this document.

### 3. Secret references for the PIN

The `pin_source` field accepts three formats:

| Format | Example | Description |
|--------|---------|-------------|
| `env:VAR` | `env:HSM_PIN` | Read PIN from environment variable `VAR` |
| `file:PATH` | `file:/run/secrets/hsm-pin` | Read PIN from file at `PATH` |
| literal | `1234` | Use value directly — not recommended for production |

### 4. Key wrapping mechanism

The PKCS#11 mechanism used for key wrapping MUST be an authenticated or
integrity-protected mechanism. Recommended choices:

- `CKM_AES_KEY_WRAP` (RFC 3394, preferred)
- `CKM_AES_KEY_WRAP_PAD` (RFC 5649, for arbitrary-length plaintexts)

ECB, CBC without authentication, and NULL mechanisms are **not** acceptable.

### 5. Session lifecycle

| Event | Required behaviour |
|-------|--------------------|
| `NewHSMKeyManager` | `C_Initialize` → `C_OpenSession` (R/W or R/O depending on HSM policy) → find wrapping key by `CKA_LABEL` |
| `WrapKey` | `C_EncryptInit(mechanism, wrappingKey)` → `C_Encrypt(plaintext)` |
| `UnwrapKey` | `C_DecryptInit(mechanism, wrappingKey)` → `C_Decrypt(ciphertext)` |
| `HealthCheck` | `C_GetTokenInfo` on the configured slot; verify `CKF_TOKEN_PRESENT` |
| `Close` | `C_CloseSession` → `C_Finalize` (idempotent; safe to call multiple times) |

### 6. Concurrency

PKCS#11 sessions are **not** thread-safe. The adapter MUST either:

- Use a session pool (recommended), or
- Serialize all PKCS#11 calls behind a mutex.

The `KeyManager` interface invariant (concurrent-safe) MUST be upheld regardless
of the chosen approach.

### 7. Zeroization

After `C_Decrypt` returns the plaintext DEK, the adapter MUST zero the local
plaintext copy before returning the slice to the caller (the caller owns the
returned slice and is responsible for their own zeroization per the
`UnwrapKey` invariant).

### 8. Error mapping

PKCS#11 `CKR_*` errors MUST be wrapped with the appropriate sentinel:

| PKCS#11 error | Sentinel |
|---------------|----------|
| `CKR_KEY_HANDLE_INVALID`, `CKR_KEY_NOT_FOUND` | `ErrKeyNotFound` |
| `CKR_ENCRYPTED_DATA_INVALID`, `CKR_UNWRAPPING_KEY_HANDLE_INVALID` | `ErrUnwrapFailed` |
| `CKR_TOKEN_NOT_PRESENT`, `CKR_DEVICE_ERROR`, `CKR_DEVICE_REMOVED` | `ErrProviderUnavailable` |

---

## Consequences

- The `hsm` build tag keeps the default binary free of cgo and C library
  dependencies.
- Operators can test configuration syntax without an HSM present; the stub
  returns a clear error message instead of a panic.
- Third-party implementers only need to satisfy the `KeyManager` interface and
  pass `ConformanceSuite`; they do not need to modify engine code.
- Functional PKCS#11 implementation is tracked as a v1.0 work item.
