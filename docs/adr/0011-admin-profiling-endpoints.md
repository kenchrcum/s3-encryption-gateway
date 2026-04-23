# ADR 0011 — Admin Profiling Endpoints (pprof)

- **Status:** Accepted (2026-04-23)
- **Owner:** Observability
- **Labels:** `milestone:v0.6`, `area:observability`, `area:admin`, `area:security`
- **Relates to:** V0.6-OBS-1, ADR 0007 (admin subsystem), V0.6-PERF-1, V0.6-PERF-2

---

## Context

After V0.6-PERF-1 (zero-copy streaming) and V0.6-PERF-2 (retry policy), the
gateway ships multiple new runtime knobs (`max_part_buffer`, retryer back-off,
per-operation attempt counts). Tuning these knobs in production rationally
requires access to CPU and heap profiles — without a code change.

Today, profiling requires temporarily importing `net/http/pprof` and rebuilding
the binary. Under any reasonable change-management process, a "debug build" is
a production incident risk.

ADR 0007 delivered precisely the primitive needed: an authenticated, TLS-
capable, rate-limited admin listener on a separate port. This ADR records the
decision to mount pprof on that listener rather than on the data-plane.

## Decision

### Where to mount

pprof endpoints are mounted **exclusively on the admin listener**
(`internal/admin/profiling.go`). Mounting on the data-plane mux
(`cmd/server/main.go:602`) is **explicitly forbidden** because:

1. The data-plane serves unauthenticated S3 API calls. Exposing a goroutine
   dump or heap histogram to any S3 client is a material information disclosure.
2. pprof CPU profiles and execution traces hold the handler goroutine for up to
   `seconds=` (default 30 s), creating a head-of-line blocking risk on shared
   muxes.
3. The admin listener already provides bearer-token auth, TLS, and a rate
   limiter — reusing those gives zero new auth surface.

Reference: Adkins et al., *Building Secure and Reliable Systems*
(O'Reilly, 2020), Ch. 15 "Debugging and Investigating Systems": "debugging
interfaces must be authenticated, authorized, and audited, or they become a
privilege-escalation vector."

### Auth model

pprof endpoints inherit the admin bearer token. No new roles or credentials
are introduced. If/when RBAC lands (v0.7 candidate), pprof inherits it
automatically.

### Opt-in with fail-closed validation

`admin.profiling.enabled` defaults to `false`. When `true`:

- `admin.enabled` must also be `true` (validated at `LoadConfig`).
- On a non-loopback admin address, `admin.tls.enabled` must be `true`.
- Negative `block_rate` / `mutex_fraction` are rejected.
- `max_profile_seconds` must be in `[1, 600]`.

### Block/mutex profiling rates

`SetBlockProfileRate` and `SetMutexProfileFraction` default to 0 (off).
These have a documented steady-state overhead (block: ~1 %, mutex: ~2–5 %
depending on contention) per Plotka, *Efficient Go* (O'Reilly, 2022) Ch. 9.
They are exposed as opt-in knobs, not always-on, so operators consciously
accept the overhead.

### Semaphore for long-running endpoints

`/profile` and `/trace` share a semaphore of size `max_concurrent_profiles`
(default 2). Requests that cannot acquire the semaphore receive
`429 Too Many Requests` with `Retry-After: 1`. This bounds the blast radius
of an operator mistake (e.g. requesting a 600-second trace twice).

### `seconds=` query-parameter cap

`max_profile_seconds` (default 60) caps the `?seconds=` parameter on
`/profile` and `/trace`. Values outside `[1, max_profile_seconds]` receive
`400 Bad Request`. This prevents a valid-token holder from pinning a core
indefinitely.

### Audit and metrics

Every profile fetch emits:

- `pprof_fetch` audit event via `audit.Logger.LogAccessWithMetadata`, carrying
  endpoint, duration, and HTTP status.
- `s3_gateway_admin_pprof_requests_total{endpoint, outcome}` counter increment.
  Bounded cardinality: 11 paths × 4 outcomes = 44 label combinations.
  Reference: Pivotto & Brazil, *Prometheus: Up & Running, 2nd Ed.*
  (O'Reilly, 2023) Ch. 4 "Instrumentation" — bounded-cardinality label design.

### Symbol table (Dockerfile)

Both `Dockerfile` and `Dockerfile.fips` now accept `STRIP_SYMBOLS=false` as
a build-arg. When set, `-w -s` is omitted from the linker flags, producing a
binary whose pprof output shows function names instead of hex addresses.
`-trimpath` is always set for reproducibility. The `make profile-image` target
builds this variant conveniently.

## Alternatives Rejected

### A. Mount on the data-plane listener

Rejected. Unauthenticated, capacity risk, information disclosure. See §"Where
to mount" above.

### B. A separate profiling-only listener

Rejected. Adds a new listener, new TLS config, new auth surface. The admin
listener already exists and is precisely the right primitive.

### C. Always-on pprof (Go default, blank import)

Rejected. The `_ "net/http/pprof"` import side-effect mounts on
`http.DefaultServeMux` which we do not use as our serving mux. More
importantly, "always-on without auth" violates the BSRS Ch. 15 mandate.

### D. Separate bearer token for profiling

Rejected. Implies a partial RBAC system the admin subsystem does not have.
If RBAC lands (v0.7), the pprof routes inherit it. Until then, the admin
token is the admin token.

## Consequences

- **Zero-config impact.** Profiling disabled by default; existing deployments
  are unaffected.
- **No new auth surface.** All security properties are inherited.
- **Operator-visible.** `gateway_admin_profiling_enabled` gauge is visible
  in Grafana dashboards alongside the existing `gateway_admin_api_enabled`
  gauge.
- **Forward-compatible.** `RegisterPprofRoutes` is a stable function
  signature; a future RBAC or role-check wrapper can be inserted without
  breaking callers.

## References

1. Bartlomiej Plotka, *Efficient Go* (O'Reilly, 2022), Ch. 9–10 — pprof
   methodology, block/mutex overhead numbers.
2. Adkins, Beyer et al., *Building Secure and Reliable Systems*
   (O'Reilly, 2020), Ch. 15 — authenticated/audited debug surfaces.
3. Julien Pivotto, Brian Brazil, *Prometheus: Up & Running, 2nd Edition*
   (O'Reilly, 2023), Ch. 4 — bounded-cardinality label design.
4. William Kennedy, *Ultimate Go: Advanced Concepts* (Pearson, 2024) —
   production symbolication and `-ldflags` trade-offs.
5. ADR 0007 — admin subsystem design (bearer auth, rate limiter, TLS gating).
