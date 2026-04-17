# FIPS 140-3 Compliance

This document describes the FIPS 140-3 compliance profile for the S3 Encryption Gateway and how to build and deploy FIPS-compliant deployments.

## Overview

The S3 Encryption Gateway offers an **optional**, **opt-in** FIPS 140-3 build profile that restricts cryptography to FIPS-approved algorithms and uses a validated cryptographic module under the hood.

When enabled, the FIPS profile:
- Restricts algorithm selection to FIPS 140-3 approved primitives only
- Uses Go 1.25+'s native FIPS 140-3 module (`crypto/fips140`)
- Requires environment variables for runtime FIPS mode activation
- Performs power-on self-tests (KATs) at program startup
- Fails closed if the environment does not match the binary's expectations

## Audience

- **Operators**: Organizations with regulatory requirements (FedRAMP, DoD, etc.) that mandate FIPS-compliant cryptography
- **Auditors**: Security teams evaluating compliance posture
- **Developers**: Contributors extending FIPS support

## Important Disclaimer

This implementation is **not** a CMVP (Cryptographic Module Validation Program) submission. Instead, we rely on Go's upstream FIPS module validation and document which algorithms the gateway exercises. For FedRAMP or DoD accreditation, consult with your compliance team about additional requirements.

## Approved Algorithms

| Primitive | Package | FIPS Status | Notes |
|-----------|---------|------------|-------|
| AES-256-GCM (AEAD) | `crypto/aes` + `crypto/cipher` | **Approved** (SP 800-38D) | Primary encryption algorithm |
| ChaCha20-Poly1305 (AEAD) | `golang.org/x/crypto/chacha20poly1305` | **Not approved** | Excluded in FIPS mode |
| PBKDF2-HMAC-SHA256 (KDF) | `crypto/pbkdf2` | **Approved** (SP 800-132) | Key derivation |
| HMAC-SHA256 (request auth) | `crypto/hmac`, `crypto/sha256` | **Approved** | Additional authenticated data |
| AES key-wrap | `crypto/aes` (via cipher) | **Approved** (SP 800-38F) | Memory KeyManager only |
| SHA-256 | `crypto/sha256` | **Approved** | Cryptographic hash |
| MD5 (S3 ETag only) | `crypto/md5` | *Permitted carve-out* | Non-security use; allowed under FIPS |
| TLS | `crypto/tls` + `crypto/x509` | **Approved cipher suites only** | When module is in FIPS mode |
| Random (DRBG) | `crypto/rand` | **Approved** | When module is in FIPS mode |

### Algorithm Availability by Build

#### Default (Non-FIPS) Build
- AES-256-GCM (preferred)
- ChaCha20-Poly1305

#### FIPS Build (`-tags=fips`)
- AES-256-GCM only
- ChaCha20-Poly1305 is **unavailable** and returns `ErrAlgorithmNotApproved`

## Building a FIPS-Compliant Binary

### Using the Makefile

```bash
# Build FIPS-compliant binary
make build-fips VERSION=1.0.0 COMMIT=abc1234

# The binary will be at: bin/s3-encryption-gateway-fips-1.0.0
```

### Using `go build` Directly

```bash
# Enable FIPS mode at compile time
GOFIPS140=v1.0.0 CGO_ENABLED=0 go build -tags=fips \
  -ldflags="-X main.version=1.0.0 -X main.commit=abc1234" \
  -o ./bin/s3-encryption-gateway-fips \
  ./cmd/server
```

### Docker Image

A dedicated `Dockerfile.fips` is provided:

```bash
# Build the FIPS Docker image
docker build -f Dockerfile.fips \
  --build-arg VERSION=1.0.0 \
  --build-arg COMMIT=abc1234 \
  -t myregistry/s3-encryption-gateway:1.0.0-fips .

# Push to registry
docker push myregistry/s3-encryption-gateway:1.0.0-fips
```

**Key differences from the default Dockerfile:**
- Base: `golang:1.25-bookworm` (Debian, **not** Alpine)
- Build: `GOFIPS140=v1.0.0 go build -tags=fips`
- Runtime: `gcr.io/distroless/static-debian12:nonroot`
- Environment: `GOFIPS140=v1.0.0`, `GODEBUG=fips140=on` baked in

## Running a FIPS-Compliant Gateway

### Prerequisites

1. **FIPS binary**: Built with `-tags=fips` (see above)
2. **Go 1.25 or later**: The FIPS module is a native Go feature in 1.25+
3. **Debian/Linux environment**: The FIPS module requires glibc; Alpine (musl) is not supported for FIPS

### Environment Variables

```bash
# REQUIRED: Activates the FIPS 140-3 module at runtime
export GOFIPS140=v1.0.0

# RECOMMENDED: Enables additional FIPS debug output (set to "fips140=on" for verbose mode)
export GODEBUG=fips140=on

# Run the gateway
./s3-encryption-gateway-fips -config config.yaml
```

### Startup Behavior

When the binary is compiled with `-tags=fips`, it will:

1. At startup, assert that `GOFIPS140=on` is detected by the runtime
2. If the assertion fails (FIPS module not active), exit with code 1 and log:
   ```
   FIPS 140-3 profile requested but runtime module is not active
   ```
3. Log the crypto profile status:
   ```
   level=info msg="crypto profile" fips=true
   ```
4. Set the `gateway_fips_mode` Prometheus metric to 1 (enabled)

### Failure Modes

**If FIPS binary is run without `GOFIPS140=v1.0.0`:**
```
$ GOFIPS140=off ./s3-encryption-gateway-fips -config config.yaml
time="2025-04-17T10:00:00Z" level=fatal msg="FIPS profile assertion failed" 
  error="FIPS 140-3 profile requested but runtime module is not active..."
```

**If attempting to use ChaCha20-Poly1305 in FIPS mode:**
```
error="crypto: algorithm not FIPS-approved in this build"
```

## Operational Guarantees

In FIPS mode, the gateway provides:

1. **Algorithm enforcement**: Non-approved algorithms cannot be instantiated, even via misconfiguration
2. **Power-on self-tests (KATs)**: Automatically run at process startup
3. **Conditional self-tests (DRBG)**: Run by the Go runtime
4. **Module boundary**: All cryptographic operations occur within the validated module
5. **Deterministic failure**: If the FIPS module is not active, the binary fails immediately at startup (fail-closed)

## Known Limitations

1. **No ChaCha20-Poly1305 in FIPS mode**: Modern and fast, but not on the FIPS-approved list
2. **No Argon2id or scrypt key derivation**: Both are unavailable under FIPS; PBKDF2 is the approved alternative
3. **No nonce-misuse resistant schemes**: AES-256-GCM-SIV is not part of this scope (would require on-disk format changes)
4. **TLS hardening**: See [docs/TLS.md](TLS.md) for FIPS-compatible TLS configuration (separate work)

## Auditor Evidence

### Cryptographic Module Boundary

The FIPS module boundary in Go 1.25+ includes:
- `crypto/aes`
- `crypto/cipher` (GCM mode)
- `crypto/sha256`, `crypto/sha512`
- `crypto/hmac`
- `crypto/pbkdf2`
- `crypto/rand`
- `crypto/fips140`

When `GOFIPS140=v1.0.0` is active, non-approved algorithms in stdlib will panic or return errors.

### Algorithm Inventory

This gateway exercises the following approved algorithms when built with `-tags=fips`:

| Operation | Algorithm | Details |
|-----------|-----------|---------|
| Object encryption | AES-256-GCM | 256-bit key, 96-bit nonce, 128-bit tag |
| Key derivation | PBKDF2-HMAC-SHA256 | 100,000 iterations, 32-byte key |
| Request authentication | HMAC-SHA256 | Variable-length authentication |
| Metadata hashing | SHA-256 | For integrity verification |
| Random generation | Go DRBG | Seeded by `/dev/urandom` (Linux) |
| TLS | Go-approved cipher suites | Hardened by FIPS module |

### CMVP Reference

The S3 Encryption Gateway relies on:
- **Go FIPS Module Version**: v1.0.0 (or later)
- **CMVP Certificate**: Reference Go's upstream FIPS validation (go.dev/security/fips140)
- **Validation Status**: Refer to NIST's CMVP database for current status

## Testing

### Local FIPS Testing

```bash
# Run tests in FIPS mode
GOFIPS140=v1.0.0 make test-fips

# Run specific FIPS test
go test -v -tags=fips -run TestChaCha20Rejected ./internal/crypto
```

### Unit Tests

The test suite includes build-tag-specific assertions:

**In FIPS mode (`-tags=fips`):**
- `TestChaCha20Rejected`: Verifies ChaCha20 returns `ErrAlgorithmNotApproved`
- `TestAESGCMApproved`: Verifies AES-256-GCM works correctly
- `TestFIPSRuntimeEnabled`: Confirms `crypto/fips140.Enabled()` is true
- `TestDefaultAlgorithmConfigFIPS`: Validates algorithm registry excludes ChaCha20

**In default mode:**
- `TestChaCha20Registered`: Verifies both algorithms are available
- `TestFIPSDisabled`: Confirms `FIPSEnabled()` returns false

## Deployment Considerations

### Kubernetes

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: s3-encryption-gateway-fips
spec:
  containers:
  - name: gateway
    image: myregistry/s3-encryption-gateway:1.0.0-fips
    env:
    - name: GOFIPS140
      value: "v1.0.0"
    - name: GODEBUG
      value: "fips140=on"
    ports:
    - containerPort: 8080
```

### Docker Compose

```yaml
services:
  gateway:
    image: myregistry/s3-encryption-gateway:1.0.0-fips
    environment:
      GOFIPS140: "v1.0.0"
      GODEBUG: "fips140=on"
    ports:
      - "8080:8080"
```

### Helm

Use the `values.fips.yaml` overlay. It ships the FIPS image tag and injects
`GOFIPS140=v1.0.0` / `GODEBUG=fips140=on` into the container via the chart's
`extraEnv` field — no post-install patching required.

```bash
helm install s3-encryption-gateway \
  -f helm/s3-encryption-gateway/values.yaml \
  -f helm/s3-encryption-gateway/values.fips.yaml \
  ./helm/s3-encryption-gateway
```

Verify the rendered Deployment carries the environment variables:

```bash
helm template release-name helm/s3-encryption-gateway \
  -f helm/s3-encryption-gateway/values.yaml \
  -f helm/s3-encryption-gateway/values.fips.yaml \
  | grep -A1 GOFIPS140
```

## Monitoring

### Prometheus Metrics

The gateway exposes a `gateway_fips_mode` gauge:

```
# HELP gateway_fips_mode FIPS 140-3 mode status (1=enabled, 0=disabled)
# TYPE gateway_fips_mode gauge
gateway_fips_mode 1
```

### Logs

Look for the startup banner:

```
time="2025-04-17T10:00:00Z" level=info msg="crypto profile" fips=true
```

If FIPS mode fails to activate:

```
time="2025-04-17T10:00:00Z" level=fatal msg="FIPS profile assertion failed" error="..."
```

## References

### O'Reilly Learning

- **"Designing to FIPS 140: A Guide for Engineers and Programmers"** (Johnston & Fant, Apress 2024, ISBN 9798868801259)
  - Module boundary principles
  - Power-on self-test expectations
  - API-level algorithm rejection (defense in depth)

- **"Serious Cryptography, 2nd Edition"** (Aumasson, No Starch 2024, ISBN 9781098182472)
  - ChaCha20-Poly1305 status on FIPS-approved list
  - AEAD algorithm guidance

### NIST Standards

- **SP 800-38D**: Recommendation for GCM Mode (AES-256-GCM)
- **SP 800-38F**: Recommendation for Key Wrap (AES-KW)
- **SP 800-132**: Password-Based Key Derivation Function (PBKDF2)
- **SP 800-131A**: Transitions: Recommendation for Transitioning the Use of Cryptographic Algorithms and Key Lengths

### Go Documentation

- [Go 1.25 Release Notes](https://go.dev/doc/go1.25)
- [crypto/fips140 Package](https://pkg.go.dev/crypto/fips140)
- [Go Security Policy](https://go.dev/security/policy)

## FAQ

### Q: Is this FIPS-certified?
**A:** No. This is a FIPS *profile*, not a FIPS *certification*. We rely on Go's upstream FIPS module validation. For regulatory submission (FedRAMP, DoD), consult your compliance team about CMVP procedures.

### Q: Can I use ChaCha20-Poly1305 in FIPS mode?
**A:** No. ChaCha20-Poly1305 is not on the FIPS-approved list, even though it is cryptographically strong. The FIPS binary will reject it at the API boundary.

### Q: What if I misconfigure the algorithm in FIPS mode?
**A:** The gateway will fail at startup with a clear error. All FIPS enforcement happens at the API boundary, not just at build time.

### Q: Do I need to change my data format to use FIPS?
**A:** No. The default encryption envelope format (AES-256-GCM + PBKDF2) is FIPS-approved and remains unchanged. Existing encrypted objects can be decrypted without modification.

### Q: Why Debian, not Alpine?
**A:** The Go FIPS module requires glibc; Alpine uses musl, which lacks certain standard library behaviors the module expects.

### Q: How do I verify the binary is really FIPS-compiled?
**A:** Check the startup log for `crypto profile fips=true`. If FIPS mode is not active at runtime, the process exits with code 1 and logs a clear error.

## Support

For issues or questions:
1. Check the [FIPS test suite](../internal/crypto/algorithms_fips_test.go)
2. Review [ADR 0005: FIPS Crypto Profile](../docs/adr/0005-fips-crypto-profile.md)
3. Open an issue on [GitHub](https://github.com/anomalyco/s3-encryption-gateway/issues)
