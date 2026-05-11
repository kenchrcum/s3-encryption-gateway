# ADR 0012 — Unified Credential Store (V1.0-AUTH-1)

**Status:** Accepted  
**Date:** 2026-05-11  
**Deciders:** Engineering, Security  
**Milestone:** v1.0 — V1.0-AUTH-1  
**Plan:** `docs/plans/V1.0-AUTH-1-plan.md`

---

## Context

The gateway historically operated in two distinct runtime modes:

1. **Single-bucket proxy mode** (`proxied_bucket` set). All traffic was
   directed to one backend bucket. Authentication was optional: requests
   without credentials were accepted and received decrypted content.
2. **Multi-bucket passthrough mode** (`use_client_credentials: true`).
   Client credentials were forwarded verbatim to the backend. This supported
   multi-tenancy but did not validate requests at the gateway — the backend
   made the auth decision.

### Problem Statement

- **Unauthenticated access to decrypted content.** Any request that arrived
  without credentials could reach the object handlers and receive plaintext
  data. This is a direct instance of [CWE-306: Missing Authentication for
  Critical Function](https://cwe.mitre.org/data/definitions/306.html).
- **Dual-mode branching.** Every request path carried conditional logic for
  "do we auth at the gateway or passthrough to the backend?" This
  complicated testing, auditing, and reasoning about security properties.
- **`use_client_credentials` did not support SigV4.** The passthrough mode
   forwarded the `Authorization` header to the backend, but the backend's
   SigV4 signature verification would fail because the gateway-terminated
   `Host` header differed from the header the client signed. This left
   query-parameter (V2 / pre-signed URL) auth as the only working path
   in passthrough mode.
- **`proxied_bucket` conflated two concepts.** It acted as both a bucket
   filter ("only this bucket") and a mode switch ("disable auth"). These
   should be independent concerns.

## Decision

Move to a **single, unified authentication flow** with a gateway-managed
credential store.

1. **Gateway-managed credentials.** A new `auth.credentials` list in the
   configuration holds the valid access-key / secret-key pairs for the
   gateway itself. These are independent of any backend credentials.
2. **Mandatory authentication.** Every incoming request must present valid
   credentials using one of the supported mechanisms:
   - AWS Signature Version 4 header (`Authorization: AWS4-HMAC-SHA256 ...`)
   - AWS Signature Version 4 presigned URL (`X-Amz-Algorithm=AWS4-HMAC-SHA256`)
   - AWS Signature Version 2 / query-parameter auth (legacy compatibility)
3. **AuthMiddleware runs before all handlers.** Credential validation is
   performed in a dedicated middleware layer. No request reaches the S3
   handlers without first passing authentication. This closes the
   CWE-306 gap.
4. **`proxied_bucket` retained as optional bucket filter.** When set, it
   restricts outbound requests to a single bucket, but it no longer
   disables authentication. It is now orthogonal to auth mode.
5. **`backend.use_client_credentials` removed.** The passthrough mode is
   deleted. All requests are validated against the gateway credential
   store; the gateway then uses its own backend credentials
   (`backend.access_key` / `backend.secret_key`) for backend calls.

## Consequences

### Positive

- **Single auth flow.** One path through the code for all requests — no
  dual-mode branching, no untested edge cases where auth is skipped.
- **SigV4 works.** The gateway verifies the client signature and then
  re-signs backend requests with its own credentials, eliminating the
  host-header mismatch problem.
- **Multi-credential support.** Multiple `auth.credentials` entries allow
  distinct access keys for different teams or services, each auditable
  independently.
- **Simpler security audit.** The auth boundary is unambiguous: the
  middleware. No handler needs to reason about whether auth happened.

### Negative

- **Breaking change: unauthenticated access is blocked.** Deployments that
  previously relied on `proxied_bucket` without credentials will reject
  all traffic after upgrade until `auth.credentials` is configured.
- **Migration effort required.** All existing deployments must add at
  least one entry to `auth.credentials` before upgrading to v1.0.

## Security Properties

- **Fail-closed.** If `auth.credentials` is empty, the gateway refuses to
  start. There is no "open by default" mode.
- **Constant-time comparison.** Secret-key verification uses
  `crypto/hmac.Equal` to resist timing side-channels.
- **Credential isolation.** Gateway credentials (what clients present) are
  never the same key material used for backend authentication. Compromise
  of a gateway credential does not grant backend access.
- **No plaintext credentials in logs.** The credential store and middleware
  never log raw secret keys. Access keys are logged for audit purposes
  only.

## Migration Path

| Previous deployment | Action required |
|---|---|
| Unauthenticated (`proxied_bucket` only) | Generate a credential pair, add to `auth.credentials`, configure all S3 clients to use it. |
| `use_client_credentials` passthrough | Remove `backend.use_client_credentials`, add the same client credentials to `auth.credentials`. Clients can continue using the same keys; the gateway now validates them instead of forwarding them. |
| `proxied_bucket` + optional client auth | Add `auth.credentials`. `proxied_bucket` stays; no other changes. |

## Alternatives Considered

### A. Per-IP allowlist

**Rejected.** IP-based allowlists do not scale in containerised and
Kubernetes environments where pod IPs are ephemeral. They also provide
no credential rotation or audit trail.

### B. Mutual TLS (mTLS)

**Rejected.** mTLS is well-suited for service-to-service mesh scenarios,
but standard S3 SDKs expect AWS signature-based authentication. Requiring
mTLS would break compatibility with all mainstream clients (AWS CLI,
boto3, `aws-sdk-go-v2`, `minio-go`) without custom transport plugins.

### C. OAuth2 / OIDC token exchange

**Rejected.** While modern in principle, OAuth2 or OIDC would be a
massive SDK compatibility break. No mainstream S3 client supports
OIDC-token-based S3 authentication out of the box; it would require
bespoke auth plugins in every client environment. The operational and
adoption cost far exceeds the security benefit over HMAC-based
signatures for this threat model.

## References

1. `docs/plans/V1.0-AUTH-1-plan.md` — implementation plan and rollout
timeline.
2. `docs/issues/v1.0-issues.md#V1.0-AUTH-1` — parent issue and acceptance
criteria.
3. [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
