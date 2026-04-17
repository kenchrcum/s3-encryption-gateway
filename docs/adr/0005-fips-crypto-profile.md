# ADR-0005 — FIPS 140-3 Crypto Profile (Optional)

**Status:** Accepted (shipped in v0.6)
**Deciders:** Crypto team
**Date:** 2026-04-17

---

## Context

Several prospective operators of `s3-encryption-gateway` serve regulated
workloads (FedRAMP, DoD, healthcare) where cryptography must be restricted to
FIPS 140-3 approved algorithms executed inside a validated cryptographic
module. V0.6-SEC-2 (`docs/plans/V0.6-SEC-2-plan.md`) defines an **optional,
opt-in** FIPS build profile for the gateway.

Two design constraints shape the decision:

1. **Module, not algorithm.** As documented in Johnston & Fant,
   *Designing to FIPS 140: A Guide for Engineers and Programmers* (Apress 2024),
   FIPS compliance is a property of the *module* housing the algorithm, not of
   the algorithm invocation itself. A program that calls AES-256-GCM is only
   FIPS-compliant if the AES implementation resides in a validated module
   whose power-on self-tests pass before any approved service runs.
2. **Algorithm selection is narrower than the gateway's default set.** The
   default build uses AES-256-GCM **and** ChaCha20-Poly1305. ChaCha20-Poly1305
   is a strong modern AEAD but is **not on the FIPS-approved list**
   (Aumasson, *Serious Cryptography, 2nd ed.*, No Starch 2024). The FIPS build
   must therefore remove it from the algorithm registry and reject it at the
   API boundary.

---

## Decision

### 1. Use Go 1.25's native FIPS 140-3 module

Go 1.25+ ships a **pure-Go** FIPS 140-3 cryptographic module (`crypto/fips140`)
that works with `CGO_ENABLED=0` and is undergoing CMVP validation. We adopt
this module rather than:

- `GOEXPERIMENT=boringcrypto` (requires CGO + glibc, more complex to build,
  less portable),
- bespoke third-party FIPS libraries (larger attack surface, separate audit).

The FIPS module is activated at **build time** with `GOFIPS140=v1.0.0` and at
**runtime** with `GODEBUG=fips140=on`.

### 2. Gate the profile behind a `fips` build tag

Mirror the `hsm` / `!hsm` pattern introduced in V0.6-SEC-1
(`keymanager_hsm.go` / `keymanager_hsm_stub.go`):

- `internal/crypto/algorithms_default.go` (`//go:build !fips`) registers both
  AEADs.
- `internal/crypto/algorithms_fips.go` (`//go:build fips`) registers only
  AES-256-GCM.
- `internal/crypto/createaead_default.go` / `createaead_fips.go` implement the
  cipher factory; the FIPS variant returns `ErrAlgorithmNotApproved` when
  ChaCha20 is requested.
- `internal/crypto/fips_profile.go` / `fips_profile_stub.go` expose
  `FIPSEnabled()` and `AssertFIPS()`.

The `fips` build is entirely optional. The default image and behaviour are
unchanged for users who do not opt in.

### 3. Defence in depth: reject at the API boundary, not just at build time

Per Johnston & Fant, algorithm exclusion must happen at the **API boundary**
as well as via build-tag exclusion, so misconfiguration cannot silently fall
back to a non-approved primitive. `createAEADCipher("ChaCha20-Poly1305", …)`
in the FIPS build returns `ErrAlgorithmNotApproved` — wrapping the build-time
exclusion in an explicit runtime sentinel.

### 4. Migrate PBKDF2 to stdlib unconditionally

Go 1.24 moved PBKDF2 into the standard library (`crypto/pbkdf2`), inside the
FIPS module boundary. Because the project already targets `go 1.25.0`, we
migrate **all** callers (non-FIPS and FIPS alike) from
`golang.org/x/crypto/pbkdf2` to `crypto/pbkdf2` — no build-tag shim. This
reduces the external-dependency surface and avoids any possibility of a FIPS
build silently using a non-module PBKDF2. A KAT regression test
(`internal/crypto/pbkdf2_kat_test.go`) locks the output vector.

### 5. Fail closed at startup

`cmd/server/main.go` calls `crypto.AssertFIPS()` immediately after the first
log line. In a `fips`-tagged binary, the call returns an error when
`crypto/fips140.Enabled()` is false (i.e., operator forgot `GOFIPS140=v1.0.0`
or set `GOFIPS140=off`). The process exits with code 1 via `logger.Fatal`
before any request is served. Non-FIPS binaries return `nil` trivially.

A Prometheus gauge `gateway_fips_mode` (0/1) and a structured log line
`crypto profile fips=true` make the active mode observable to operators and
scrapers.

### 6. Separate container image, not a conditional in the default one

A dedicated `Dockerfile.fips` builds on `golang:1.25-bookworm` (Debian —
glibc-backed, required by the FIPS module; Alpine's musl is not supported)
and runs on `gcr.io/distroless/static-debian12:nonroot`. The default image
remains Alpine-based and keeps its current footprint.

### 7. Not a CMVP submission

This profile relies on Go's upstream FIPS module and its CMVP status. The
gateway does not claim independent validation. Auditors are directed to
`docs/FIPS.md` for the algorithm inventory, evidence list, and the upstream
CMVP certificate reference.

---

## Consequences

### Positive
- Operators with regulatory requirements can deploy a FIPS image without any
  custom build process.
- No behavioural drift for users who do not opt in.
- One external crypto dependency (`golang.org/x/crypto/pbkdf2`) is retired
  across both builds.
- Defence-in-depth: a misconfigured FIPS build cannot silently fall back to a
  non-approved AEAD.

### Negative
- Two container images to publish (`<ver>` and `<ver>-fips`).
- ChaCha20-Poly1305 cannot be used by FIPS operators even for performance on
  CPUs lacking AES-NI — they lose roughly the same performance they already
  lose by running in FIPS mode.
- The FIPS test matrix adds CI wall-clock time (`GOFIPS140=v1.0.0 go test
  -tags=fips -race ./...`).

### Neutral
- On-disk envelope format is unchanged (AES-256-GCM + PBKDF2 is the default
  and is FIPS-approved), so FIPS and non-FIPS deployments can interoperate at
  the data level.

---

## Alternatives considered

| Alternative | Why rejected |
| ----------- | ------------ |
| `GOEXPERIMENT=boringcrypto` | Requires CGO + glibc; incompatible with the default Alpine image; larger build complexity. |
| Make FIPS the default and drop ChaCha20 everywhere | Breaks existing deployments that rely on ChaCha20; no benefit for non-regulated users. |
| Wrap an external FIPS library (e.g. wolfCrypt) | Adds C dependency, separate audit surface, maintenance burden; offers no practical gain over the Go 1.25 native module. |
| Build-tag shim around PBKDF2 only | Leaves `golang.org/x/crypto/pbkdf2` in the default build; two APIs to maintain; no benefit over unconditional migration given Go 1.25 minimum. |
| Skip startup assertion, trust env vars | Operators who forget `GOFIPS140` would ship a binary silently running non-FIPS primitives; violates fail-closed principle. |

---

## References

- `docs/plans/V0.6-SEC-2-plan.md` — implementation plan.
- `docs/FIPS.md` — operator and auditor guide.
- Johnston, D. & Fant, R., *Designing to FIPS 140: A Guide for Engineers and
  Programmers* (Apress, 2024, ISBN 9798868801259).
- Aumasson, J.-P., *Serious Cryptography, 2nd Edition* (No Starch, 2024,
  ISBN 9781098182472).
- NIST SP 800-38D (GCM), SP 800-38F (Key Wrap), SP 800-132 (PBKDF2),
  SP 800-131A (algorithm transitions).
- Go 1.25 Release Notes; `crypto/fips140` package documentation.
