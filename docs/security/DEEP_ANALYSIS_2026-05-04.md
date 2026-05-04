# Deep Security Analysis — S3 Encryption Gateway (_post-v1.0-MAINT-1, 2026-05-04_)

**Analysis Date:** 2026-05-04  
**Scope:** Full repository HEAD; all packages under `internal/`, `cmd/server/`, `Dockerfile`, `Dockerfile.fips`, `.github/workflows/`  
**Methodology:** Static code analysis with symbolic resolution; cross-reference with prior findings in `docs/security/DEEP_ANALYSIS_2026-04-29.md`; best-practice comparison against OWASP ASVS L3, NIST SP 800-132 (2023), NIST SP 800-204, CIS Docker Benchmark  
**Analyst:** OpenCode (automated deep-analysis session)

---

## 1. Executive Summary

The codebase continues to demonstrate **above-average security engineering** relative to open-source infrastructure components. The hardening sprint completed before v1.0 (SEC-1 through SEC-28) is fully reflected in the current HEAD. No regressions against previously fixed findings were detected.

This analysis identifies **16 new or previously untracked findings**: 2 Critical, 7 High, 7 Medium, and 7 Low. None of the Critical or High findings represent an immediately exploitable remote vulnerability in a correctly deployed instance. They are design-level correctness and defence-in-depth gaps that should be addressed before the next major release.

**Overall security grade: A−**

---

## 2. Feature Inventory

| Layer | Package | Capabilities |
|---|---|---|
| Gateway entrypoint | `cmd/server/` | HTTP/HTTPS; graceful shutdown; FIPS assertion; middleware chain wiring |
| Crypto engine | `internal/crypto/engine.go` | AES-256-GCM + ChaCha20-Poly1305; PBKDF2 + KMS envelope; chunked streaming; range decrypt; fallback v1/v2 |
| MPU encryption | `internal/crypto/mpu_encrypter.go` | Per-upload DEK; HKDF chunk-IV derivation; streaming parts; DEK zeroization |
| Key management | `internal/crypto/keymanager_*.go` | Memory, Cosmian KMIP, HSM stub, PasswordKeyManager |
| SigV4 auth | `internal/api/auth.go` | Header + presigned validation; clock-skew enforcement; signing-oracle prevention |
| Admin API | `internal/admin/` | Bearer auth (constant-time); TLS; token rotation; pprof; rate limit |
| Middleware | `internal/middleware/` | Recovery, logging, security headers, OpenTelemetry tracing, rate limiter, bucket validation |
| Audit logging | `internal/audit/` | Structured JSON events; batch/HTTP/file/stdout sinks; field redaction |
| MPU state store | `internal/mpu/state.go` | Valkey-backed encrypted MPU state; fail-closed startup |
| Configuration | `internal/config/config.go` | YAML + env override; hot-reload; extensive validation |
| S3 client | `internal/s3/client.go` | Full S3 API; retry with backoff/jitter; Object Lock |
| Migration | `internal/migrate/` | Offline re-encryption worker |
| Ops | Helm, Dockerfiles, GitHub Actions | Multi-provider CI; coverage gate; mutation testing; FIPS CI path |

---

## 3. Findings

### 3.1 Critical

---

#### [V1.0-SEC-C01] — `defaultWriter` uses `fmt.Printf`, bypassing audit redaction

**File:** `internal/audit/audit.go:335`  
**CVSS v3.1 (estimated):** 6.5 (Medium — information exposure from audit log)  

**Description:**  
The `defaultWriter` fallback type, instantiated when `NewLogger` is called without an explicit sink, emits raw audit events via `fmt.Printf("%s\n", string(data))`. This path:

1. Is not gated by `auditLogger.redactMetadata()` — all metadata fields including keys listed in `RedactMetadataKeys` are written in plaintext.
2. Writes to process stdout, which in container environments is typically captured by a log aggregator without field-level scrubbing.
3. Is reachable in any deployment that calls `audit.NewLogger(...)` directly rather than `audit.NewLoggerFromConfig(...)` with an explicit sink type.

```go
// internal/audit/audit.go:328-341
func (w *defaultWriter) WriteEvent(event *AuditEvent) error {
    data, err := json.Marshal(event)
    if err != nil {
        return fmt.Errorf("failed to marshal event: %w", err)
    }
    // In production, you would write to a file, database, or external service
    // For now, we'll just format it (actual writing would be done by logging middleware)
    fmt.Printf("%s\n", string(data))  // <-- no redaction gate
    return nil
}
```

**Impact:** Sensitive metadata fields (object keys, algorithm identifiers, KMS key IDs) may appear unredacted in container log streams.

**Recommendation:**  
Replace `fmt.Printf` with a call to the shared `StdoutSink` (which delegates to `json.Marshal` but should apply redaction), or remove `defaultWriter` entirely and require callers to pass an explicit `EventWriter`. At minimum, run `event` through `auditLogger.redactMetadata` before marshalling.

---

#### [V1.0-SEC-C02] — `EncryptionEngine` interface does not propagate `context.Context`

**Files:** `internal/crypto/engine.go:336, 566, 1274, 1577`  
**CVSS v3.1 (estimated):** 7.5 (High — availability; DoS via goroutine leak under KMS outage)

**Description:**  
Every top-level method of `engine` (`Encrypt`, `Decrypt`, `DecryptRange`, `decryptFallbackV2`) creates `context.Background()` locally. The `EncryptionEngine` interface does not accept a `context.Context` parameter.

Consequences:
- KMS operations (`WrapKey`, `UnwrapKey` over KMIP/TLS) cannot be cancelled when the HTTP request that triggered them is cancelled or times out.
- Under a KMIP server outage, in-flight goroutines block until Go's default TCP keepalive fires (≥2 minutes). This can exhaust the goroutine pool.
- OpenTelemetry spans created inside these methods are not children of the HTTP request span; the distributed trace is broken.
- The `TODO: Accept context parameter in future refactor` comments acknowledge the debt but provide no timeline.

```go
// internal/crypto/engine.go:336
func (e *engine) Encrypt(reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
    ctx := context.Background() // TODO: Accept context parameter in future refactor
    ctx, span := e.tracer.Start(ctx, "Crypto.Encrypt", ...)
    // ...
    envelope, err = e.kmsManager.WrapKey(ctx, key, metadata)  // not cancellable
```

**Impact:** KMS outage causes request goroutines to leak until TCP timeout. In a high-concurrency deployment this is a remote DoS.

**Recommendation:**  
Change the `EncryptionEngine` interface to:
```go
Encrypt(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error)
Decrypt(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error)
DecryptRange(ctx context.Context, reader io.Reader, metadata map[string]string, start, end int64) (io.Reader, map[string]string, error)
```
Propagate the HTTP request context from handlers through the engine to KMS calls.

---

### 3.2 High

---

#### [V1.0-SEC-H01] — AAD canonicalization is injection-prone

**File:** `internal/crypto/engine.go:1801-1824`  

**Description:**  
`buildAAD` constructs Additional Authenticated Data by concatenating field values with `|` delimiters:

```go
b.WriteString("alg:" + algorithm + "|salt:" + encodeBase64(salt) + "|iv:" + encodeBase64(nonce))
if ct := meta["Content-Type"]; ct != "" {
    b.WriteString("|ct:" + ct)
}
if osz := meta[MetaOriginalSize]; osz != "" {
    b.WriteString("|osz:" + osz)
}
```

A Content-Type value that itself contains `|osz:` (e.g., `text/plain|osz:999`) can shift field boundaries. Two distinct metadata combinations can produce identical AAD bytes, undermining the integrity binding. While an attacker needs write access to S3 metadata to exploit this in practice, it violates the AAD contract.

**Recommendation:**  
Use length-prefixed encoding (TLV), a sorted JSON canonical form, or HMAC-based binding (NIST SP 800-108) for AAD construction. Example fix:

```go
func buildAAD(algorithm string, salt, nonce []byte, meta map[string]string) []byte {
    h := hmac.New(sha256.New, salt)
    h.Write([]byte(algorithm))
    h.Write(nonce)
    // length-prefix each field value
    for _, key := range []string{"Content-Type", MetaKeyVersion, MetaOriginalSize} {
        v := meta[key]
        binary.Write(h, binary.BigEndian, uint32(len(v)))
        h.Write([]byte(v))
    }
    return h.Sum(nil)
}
```

---

#### [V1.0-SEC-H02] — Legacy no-AAD fallback combined with `keyResolver` creates a two-oracle attack path

**File:** `internal/crypto/engine.go:723-753`  

**Description:**  
The `Decrypt` method contains a layered fallback:
1. Try AAD-authenticated decryption.
2. If that fails and `MetaLegacyNoAAD == "true"`, try without AAD.
3. If still failing and a `keyResolver` is present, try each alternative key — and also try no-AAD with each alternative key (line ~749).

An adversary with S3 backend write access can set `MetaLegacyNoAAD=true` on any object. This converts a failed AAD-authenticated decryption into an unauthenticated decryption attempt across all versions in the `keyResolver` history, effectively bypassing the AAD integrity guarantee for every historical key version.

```go
if openErr != nil && !usingKMS && e.keyResolver != nil {
    // ...
    if pt, err3 := altGCM.Open(nil, iv, ciphertext, aad); err3 == nil {
        // success
    } else if expandedMetadata[MetaLegacyNoAAD] == "true" {
        if pt2, err4 := altGCM.Open(nil, iv, ciphertext, nil); err4 == nil {
            // <-- no-AAD with historical key — bypasses AAD for any key version
        }
    }
}
```

**Note on migration tool:**  
`internal/migrate/migrator.go` provides `BackfillLegacyNoAAD` (metadata-only pass) and re-encrypts `ClassB_NoAAD` objects via the full `Migrate` pipeline. This handles all **legitimately pre-AAD** objects. However the migration tool does **not** close the attack vector described here: an adversary with S3 backend write access can set `MetaLegacyNoAAD=true` on a **modern** object at any time, regardless of whether a migration has been run. The fallback code path exists permanently in the runtime engine and remains reachable.

**Why this is not obsoleted by the migration tool:**  
The migration tool's purpose is to mark and re-encrypt genuine legacy objects. The security issue is that the metadata flag used to signal "this is a legacy object" (`MetaLegacyNoAAD`) is an unauthenticated, attacker-writable S3 metadata field. Any object — including freshly written modern objects — can be retroactively labelled as legacy by anyone with S3 write access, triggering the no-AAD + multi-key fallback in the engine. The migration tool cannot prevent this.

**Recommendation:**  
Remove the `MetaLegacyNoAAD` check from the `keyResolver` branch entirely. Since `BackfillLegacyNoAAD` and `Migrate` already exist to handle all genuine pre-AAD objects, no deployment should have remaining `ClassB_NoAAD` objects after running the migration. The two-step fix is:

1. Run the migration tool to completion on all buckets (`BackfillLegacyNoAAD` + `Migrate --filter=sec4`).
2. Remove the inner `else if expandedMetadata[MetaLegacyNoAAD] == "true"` block from the `keyResolver` branch in `engine.go`. The outer single-key no-AAD fallback for the current key is a separate concern and can be evaluated independently.

---

#### [V1.0-SEC-H03] — PBKDF2-SHA256 iteration count is below current NIST recommendation

**File:** `internal/crypto/engine.go:25`  

**Description:**  
```go
pbkdf2Iterations = 100000
```

NIST SP 800-132 (2023 revision) recommends a minimum of 600,000 iterations for PBKDF2-SHA256 for password-derived keys. OWASP's 2021 recommendation (now superseded) was 100,000; the current recommendation is ≥600,000 or migration to argon2id. At 100k iterations, an attacker with access to a PBKDF2 salt and ciphertext can run offline brute-force attacks roughly 6× faster than the NIST floor.

**Impact:** Offline brute-force of password-derived encryption keys is feasible for weak or medium-strength passwords if any (salt, ciphertext) pair is exfiltrated.

**Recommendation:**  
Increase `pbkdf2Iterations` to 600,000, or migrate to `golang.org/x/crypto/argon2` (`argon2.IDKey`) with parameters `time=3, memory=65536, threads=4`. Note: a migration plan is required because existing ciphertext uses the old iteration count stored in metadata.

---

#### [V1.0-SEC-H04] — SigV4 validation evaluates `time.Now()` twice; credential-scope date not cross-validated against `X-Amz-Date`

**File:** `internal/api/auth.go:127, 155-173`  

**Description:**  
Two separate issues in `ValidateSignatureV4`:

1. **Double clock evaluation:** The clock-skew check at line 127 calls `time.Since(t)`, which internally calls `time.Now()`. The presigned expiry check at line 167 calls `time.Now().UTC()` independently. Between the two evaluations the system clock (or NTP adjustment) can differ. The correct pattern is `now := time.Now().UTC()` captured once at the top of the function.

2. **Credential-scope date vs. `X-Amz-Date` not cross-validated:** The signing key is derived from the `date` extracted from `credentialScope` (from the `Credential=` field). The clock-skew check validates the `timestamp` from `X-Amz-Date`. These two dates are never compared. An attacker can craft a request where `Credential=key/20200101/region/s3/aws4_request` (an old date, matching an old PBKDF2-derived key the gateway still accepts via `keyResolver`) while `X-Amz-Date` is within the current clock-skew window. The signature will verify against the old key, effectively replaying old credentials.

**Recommendation:**  
```go
now := time.Now().UTC()
// clock-skew check
if now.Sub(t).Abs() > clockSkew { return error }
// presigned expiry check
if isPresigned && now.After(t.Add(duration)) { return error }
// cross-validate credential date
credDate := scopeParts[0] // "20060102" from credentialScope
if credDate != t.Format("20060102") { return error }
```

---

#### [V1.0-SEC-H05] — Admin bearer token not zeroized on shutdown

**File:** `internal/admin/server.go`  

**Description:**  
The `tokenCache []byte` field holds the bearer token in memory. On inline token mode, the token lives in a closure-captured `[]byte` slice. Neither is zeroed during `Shutdown()`. An attacker with post-shutdown memory access (container snapshot, process core dump, `/proc/self/mem`) can recover the admin token.

**Recommendation:**  
Add `zeroBytes(s.tokenCache)` to `Shutdown`. For the inline token closure, expose the slice reference so it can be zeroed. Pattern used elsewhere in the codebase:
```go
func (s *Server) Shutdown(ctx context.Context) error {
    s.stopRefreshOnce.Do(func() { close(s.stopRefresh) })
    s.tokenMu.Lock()
    zeroBytes(s.tokenCache)
    s.tokenCache = nil
    s.tokenMu.Unlock()
    // ...
}
```

---

#### [V1.0-SEC-H06] — Rate limiter `requests` map is unbounded under IP-churn DDoS

**File:** `internal/middleware/security.go`  

**Description:**  
The `RateLimiter.requests` map grows one entry per unique client key. The `cleanup` goroutine removes stale entries on the configured `cleanupInterval` (defaults to `window` duration). Under an IP-churn attack (attacker cycles through many source addresses), new entries are inserted faster than the cleanup goroutine removes them. There is no cap on map size.

**Impact:** Heap exhaustion / OOM kill under sustained IP-churn DDoS.

**Recommendation:**  
Add a maximum map size. When the cap is reached, either refuse new entries (return `Allow = false`) or use an LRU eviction policy. A simple cap:
```go
const maxRateLimitClients = 100_000

func (rl *RateLimiter) Allow(key string) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    if _, exists := rl.requests[key]; !exists && len(rl.requests) >= maxRateLimitClients {
        return false // treat unknown over-capacity clients as rate-limited
    }
    // ...
}
```

---

#### [V1.0-SEC-H07] — HTTP audit sink has no configurable TLS `ClientConfig` (no custom CA, no mTLS)

**File:** `internal/audit/sink.go:237-256`  

**Description:**  
`NewHTTPSinkWithConfig` builds an `http.Transport` without setting `TLSClientConfig`. The Go default (system CA pool, server-cert verification) is used. However:
- There is no field to provide a custom CA certificate for private PKI audit endpoints.
- There is no field to configure a client certificate for mTLS.
- There is no field to set a minimum TLS version for the audit connection.

In enterprise deployments where the audit SIEM uses a private PKI, operators must add the SIEM's CA to the system trust store — a step that is easily missed and not documented.

**Recommendation:**  
Add a `TLS` sub-section to `SinkConfig` (similar to `ValkeyTLSConfig`) and use it to build the transport:
```go
type SinkTLSConfig struct {
    CAFile             string
    CertFile           string
    KeyFile            string
    InsecureSkipVerify bool
    MinVersion         string
}
```

---

### 3.3 Medium

---

#### [V1.0-SEC-M01] — `fmt.Sscanf` used for integer parsing silently accepts trailing characters

**Files:** `internal/crypto/engine.go:818,820,738`, `internal/api/handlers.go:1407,1885`, `internal/config/config.go:873,882,897,903,918`

`fmt.Sscanf(v, "%d", &n)` will parse `"100abc"` as `100` without returning an error (it matches the `%d` verb and stops). `strconv.Atoi` or `strconv.ParseInt` must be used instead to ensure the entire string is a valid integer. Silent acceptance of trailing characters can introduce logic errors or parameter confusion.

**Recommendation:** Replace all `fmt.Sscanf(v, "%d", &n)` occurrences with `strconv.Atoi(v)` or `strconv.ParseInt(v, 10, 64)` and handle the error.

---

#### [V1.0-SEC-M02] — Batch sink flush failure logged to `os.Stderr` via `fmt.Fprintf`

**File:** `internal/audit/sink.go:183`

```go
fmt.Fprintf(os.Stderr, "Failed to flush audit events after %d retries: %v\n", s.retryCount, err)
```

This bypasses the structured logger, cannot be correlated to a request ID, cannot be suppressed in tests, and is not visible in log aggregators that capture structured JSON only.

**Recommendation:** Replace with `slog.Error("audit: failed to flush events", "retries", s.retryCount, "error", err)`.

---

#### [V1.0-SEC-M03] — Config hot-reload guard is fragile (string comparison against literal `"config.yaml"`)

**File:** `cmd/server/main.go:598`

```go
if configPath != "" && configPath != "config.yaml" {
    // hot-reload enabled
}
```

Hot-reload is silently disabled when the operator explicitly passes `--config config.yaml`. This is an opt-in-by-accident mechanism. If an operator expects hot-reload and uses the default filename, they get no error and no hot-reload.

**Recommendation:** Remove the `configPath != "config.yaml"` condition. Hot-reload should be enabled for any non-empty config path, or controlled by an explicit `--hot-reload` flag.

---

#### [V1.0-SEC-M04] — Presigned `X-Amz-Expires` has no enforced maximum

**File:** `internal/api/auth.go:155-173`

The `X-Amz-Expires` value is parsed from the query string and accepted up to `int` max. AWS S3 limits presigned URL validity to 604800 seconds (7 days) for SigV4. There is no corresponding cap enforced by the gateway. A presigned URL with `Expires=2147483647` (≈68 years) is accepted as long as the clock-skew check passes.

**Recommendation:** Reject presigned URLs where `expires > 604800` (7 days), matching AWS behaviour.

---

#### [V1.0-SEC-M05] — Decompression has no expanded-size limit (decompression bomb)

**File:** `internal/crypto/engine.go` (decompression delegated to `compressionEngine.Decompress`)

After AEAD decryption, the plaintext is fed directly to `Decompress`. The `MetaCompressionOriginalSize` metadata field is stored but never used to cap the decompressor's output. A crafted object with a pathological compression ratio (e.g., a 1 KB gzip that expands to 1 GB) could exhaust heap memory.

**Recommendation:** Before calling `Decompress`, read `MetaCompressionOriginalSize` and pass a `maxBytes` limit to the decompressor (use `io.LimitReader` around the decompressed output).

---

#### [V1.0-SEC-M06] — Policy manager not reloaded during config hot-reload

**File:** `cmd/server/main.go` (`ApplyConfigChanges`)

`ApplyConfigChanges` updates rate limiter, tracing, cache, and audit logger, but does **not** reload the `policyManager`. If a policy file is modified after startup to add or remove `EncryptMultipartUploads`, the change has no effect until process restart.

**Recommendation:** Include policy reload in `ApplyConfigChanges`. The `PolicyManager.LoadPolicies` method already supports reloading; it needs to be called atomically and the handler needs to receive the new policy manager reference.

---

#### [V1.0-SEC-M07] — `ValkeyTLSConfig.MinVersion` string not validated; invalid value silently falls back to TLS 1.2

**File:** `internal/mpu/state.go` (`buildTLSConfig`)

`buildTLSConfig` parses `cfg.TLS.MinVersion` as a string. An invalid value (e.g., `"1.4"`, `"tls13"`) is silently accepted and the resulting `tls.Config.MinVersion` is left at its zero value, which Go interprets as TLS 1.2. The config comment says `MinVersion: "1.3"` is the default, but there is no validation that enforces it.

**Recommendation:** Add a validation check in `buildTLSConfig` and in `Config.Validate` that rejects values outside `{"1.2", "1.3"}`.

---

### 3.4 Low

---

#### [V1.0-SEC-L01] — `/metrics` endpoint is unauthenticated on the public data-plane port

**File:** `cmd/server/main.go:588`

```go
router.Handle("/metrics", m.Handler()).Methods("GET")
```

Prometheus metrics are served on the same port as S3 operations with no authentication. With `EnableBucketLabel: true`, bucket names appear in metric labels. Tracing metrics may reveal operation patterns and key version usage.

**Recommendation:** Move `/metrics` to the admin port (already TLS + bearer auth protected), or add an optional `metrics.auth` bearer token config option.

---

#### [V1.0-SEC-L02] — FIPS `Dockerfile.fips` has no `HEALTHCHECK` directive

**File:** `Dockerfile.fips`

The standard `Dockerfile` includes a `HEALTHCHECK` for Docker/Kubernetes availability management. `Dockerfile.fips` omits it, meaning containers built from the FIPS image report no health status.

**Recommendation:** Add the same `HEALTHCHECK` as in `Dockerfile`:
```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1
```

---

#### [V1.0-SEC-L03] — `/health` route is not registered but is referenced in `HEALTHCHECK`

**File:** `cmd/server/main.go` (no `/health` route); `Dockerfile:50`

The Dockerfile `HEALTHCHECK` probes `http://localhost:8080/health`. No route for `/health` is registered in `main.go`. Gorilla Mux returns 405 Method Not Allowed for unregistered paths. The HEALTHCHECK therefore always fails (exit 1 from `wget --spider`), causing Docker/Kubernetes to consider the container perpetually unhealthy.

**Recommendation:** Register a simple health endpoint:
```go
router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
}).Methods("GET", "HEAD")
```

---

#### [V1.0-SEC-L04] — YAML config silently ignores unknown keys (typo-blind)

**File:** `internal/config/config.go:687`

```go
if err := yaml.Unmarshal(data, config); err != nil { ... }
```

`gopkg.in/yaml.v3`'s default `Unmarshal` ignores unknown fields. A typo like `encyption:` instead of `encryption:` will be silently discarded; the gateway starts with default (possibly insecure) values and no error.

**Recommendation:** Use `yaml.Decoder` with `KnownFields(true)`:
```go
dec := yaml.NewDecoder(bytes.NewReader(data))
dec.KnownFields(true)
if err := dec.Decode(config); err != nil { ... }
```

---

#### [V1.0-SEC-L05] — Default clock-skew tolerance is 15 minutes (3× AWS default)

**File:** `internal/config/config.go:657`

```go
Auth: AuthConfig{
    ClockSkewTolerance: 15 * time.Minute,
},
```

AWS S3's own SigV4 clock-skew window is 5 minutes. A 15-minute window allows a captured Authorization header or presigned URL to be replayed for up to 30 minutes (±15). The extended window is generous relative to industry standard.

**Recommendation:** Default to 5 minutes. Operators who need more flexibility can increase it explicitly in config.

---

#### [V1.0-SEC-L06] — Tracing default exporter is `"stdout"`, producing verbose span output when tracing is enabled without explicit exporter

**File:** `internal/config/config.go:641`

```go
Exporter: "stdout",
```

When an operator enables tracing (`Tracing.Enabled: true`) without specifying an exporter, all spans are printed as JSON to stdout. In a container environment this floods log aggregators and can expose request metadata. The default should be `"none"` (no-op exporter) or require explicit exporter selection.

---

#### [V1.0-SEC-L07] — `Dockerfile` `HEALTHCHECK` uses `wget` which is not guaranteed present in all Alpine derivatives

**File:** `Dockerfile:50`

```dockerfile
CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1
```

`wget` is not installed by the `RUN apk` step in the runtime stage; only `ca-certificates` and `tzdata` are added. On stock `alpine:3.23`, `wget` is available as a BusyBox applet, but if the base image changes to a minimal Alpine derivative, this check silently fails. The more reliable pattern is to ship a small Go health-check binary, or use `curl` (explicitly installed), or probe via the Kubernetes liveness probe mechanism instead of `HEALTHCHECK`.

---

## 4. Security Strengths (Confirmed)

The following practices were verified as correctly implemented at HEAD:

| Area | Evidence |
|---|---|
| AEAD-only ciphers | AES-256-GCM + ChaCha20-Poly1305; no CBC, no ECB |
| `crypto/rand` throughout | `generateSalt`, `generateNonceForAlgorithm`, `generateDataKey` all use `rand.Read` |
| Memory zeroization | `zeroBytes()` on password (`engine.Close`), DEK (`returnEncBuf`), KMS key material, `activePassword` in `main` |
| Constant-time auth | `hmac.Equal` for SigV4 comparison; `subtle.ConstantTimeCompare` for admin bearer token |
| HKDF chunk-IV derivation | Each chunk gets a deterministic per-upload IV via HKDF-SHA256 (SEC-2 implemented) |
| Fail-closed Valkey startup | `NewValkeyStateStore` returns error if Valkey unreachable at startup |
| FIPS 140-3 build path | `GOFIPS140=v1.0.0 -tags=fips`; distroless runtime; `AssertFIPS()` at startup |
| Trusted-proxy IP extraction | Rightmost-to-leftmost XFF chain traversal with CIDR allowlist |
| Tracing sanitisation | `redactSensitive` removes Authorization, security tokens from spans; sanitised URL strips query string |
| Explicit TLS cipher suites | `buildAdminTLSConfig` sets `CipherSuites` and `CurvePreferences`; TLS 1.2 minimum |
| Structured debug logging | `slog.Debug` with lengths only; `debug-lint.sh` CI script enforces no raw crypto values |
| Admin token hygiene | File permission check (mode `0600`); min 32-byte decoded length; periodic rotation loop |
| Non-root container | UID/GID 1000 in production Dockerfile; CGO_ENABLED=0 static binary |
| Race detector CI | All unit + conformance tiers run with `-race` |
| 75% coverage gate | Enforced in CI for both default and FIPS build profiles |
| Audit field redaction | `redactMetadata` strips configurable keys before event dispatch |

---

## 5. Benchmark Assessment

| Standard | Area | Status | Notes |
|---|---|---|---|
| OWASP ASVS L3 §2.1 | Password security | Partial | PBKDF2-SHA256; upgrade to argon2id recommended (V1.0-SEC-H03) |
| OWASP ASVS L3 §6.2 | Algorithms | Pass | AES-256-GCM, ChaCha20-Poly1305 |
| OWASP ASVS L3 §6.3 | Random values | Pass | `crypto/rand` throughout |
| OWASP ASVS L3 §7.1 | Log content | Partial | `defaultWriter` bypass (V1.0-SEC-C01) |
| OWASP ASVS L3 §9.1 | Communications security | Pass | Explicit cipher suites; TLS 1.2+ minimum |
| OWASP ASVS L3 §14.4 | HTTP security headers | Pass | X-Frame-Options, CSP, HSTS, Referrer-Policy, Permissions-Policy |
| NIST SP 800-132 (2023) | KDF iteration count | Partial | 100k iterations; NIST floor is 600k (V1.0-SEC-H03) |
| NIST SP 800-204 §4.4 | Context propagation | Fail | `context.Background()` throughout engine (V1.0-SEC-C02) |
| CIS Docker Benchmark 4.1 | Non-root user | Pass | UID 1000 |
| CIS Docker Benchmark 4.6 | HEALTHCHECK | Partial | Missing in FIPS image (V1.0-SEC-L02); `/health` route absent (V1.0-SEC-L03) |
| CIS Docker Benchmark 4.9 | USER instruction | Pass | `USER gateway` in runtime stage |

---

## 6. Prioritised Remediation Roadmap

| Priority | ID | Effort | Notes |
|---|---|---|---|
| P0 | V1.0-SEC-C02 | Large — interface change | Context propagation requires updating `EncryptionEngine` interface, all callers, and chunked.go |
| P0 | V1.0-SEC-L03 | Trivial | Register `/health` route — 5 lines |
| P1 | V1.0-SEC-C01 | Small | Remove `defaultWriter` or route through `StdoutSink` with redaction |
| P1 | V1.0-SEC-H02 | Small | Remove no-AAD fallback from `keyResolver` branch |
| P1 | V1.0-SEC-H04 | Small | Capture `now` once; add credential-date cross-check |
| P2 | V1.0-SEC-H01 | Medium | Replace pipe-delimited AAD with length-prefixed or HMAC-based construction |
| P2 | V1.0-SEC-H03 | Medium | Increase PBKDF2 iterations to 600k with migration path |
| P2 | V1.0-SEC-H06 | Small | Add map-size cap to rate limiter |
| P2 | V1.0-SEC-M05 | Small | `io.LimitReader` on decompressor output bounded by `MetaCompressionOriginalSize` |
| P3 | V1.0-SEC-H05 | Small | `zeroBytes(s.tokenCache)` in `Shutdown` |
| P3 | V1.0-SEC-H07 | Medium | Add `SinkTLSConfig` to audit HTTP sink |
| P3 | V1.0-SEC-M01 | Small | Replace `fmt.Sscanf` with `strconv.Atoi`/`ParseInt` |
| P3 | V1.0-SEC-M03 | Trivial | Remove `configPath != "config.yaml"` guard |
| P3 | V1.0-SEC-M04 | Trivial | Add `Expires > 604800` rejection |
| P3 | V1.0-SEC-M06 | Medium | Wire policy reload into `ApplyConfigChanges` |
| P3 | V1.0-SEC-L04 | Small | `yaml.Decoder.KnownFields(true)` |
| P4 | V1.0-SEC-L01 | Medium | Move `/metrics` to admin port or add auth |
| P4 | V1.0-SEC-L05 | Trivial | Change default clock-skew to 5 minutes |
| P4 | V1.0-SEC-M02, V1.0-SEC-M07, V1.0-SEC-L02, V1.0-SEC-L06, V1.0-SEC-L07 | Trivial/Small | See individual recommendations |

---

## 7. Overall Security Statement

The s3-encryption-gateway remains **among the most securely engineered open-source S3 proxy implementations** available. Cryptographic primitives are correctly chosen and correctly applied. Key material lifecycle (generation, use, zeroization) is handled with discipline. The authentication layer (SigV4, admin bearer) uses constant-time comparisons and has replay-window enforcement. Fail-closed startup semantics prevent degraded-security operation.

The two Critical findings are **design gaps, not exploitable vulnerabilities in isolation**: V1.0-SEC-C01 requires the `defaultWriter` code path to be exercised in a sensitive environment; V1.0-SEC-C02 requires a KMS outage concurrent with a traffic spike. Both should be fixed, but neither indicates the project is unsafe to deploy in its current form with a properly configured external KMS and a non-default audit sink.

The High findings (V1.0-SEC-H01 through V1.0-SEC-H07) represent defence-in-depth gaps. V1.0-SEC-H02 (no-AAD two-oracle) is the most concerning because it allows backend write access to bypass AAD integrity; it should be addressed before any multi-tenant deployment.

**Recommended action before next major release:** resolve V1.0-SEC-C02 (context propagation), V1.0-SEC-L03 (`/health` route), V1.0-SEC-H02 (legacy no-AAD + keyResolver), and V1.0-SEC-H04 (double time.Now + credential-date cross-check).
