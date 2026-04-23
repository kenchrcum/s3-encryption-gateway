# Admin API Reference

The admin API runs on a **separate listener** (default `127.0.0.1:8081`),
isolated from the S3 data-plane. It provides key rotation management and
diagnostic endpoints.

## Configuration

```yaml
admin:
  enabled: true
  address: "127.0.0.1:8081"
  tls:
    enabled: false          # Required for non-loopback addresses
    cert_file: ""
    key_file: ""
  auth:
    type: bearer
    token_file: /etc/gateway/admin-token  # Recommended: file-based token
    # token: ""              # Dev only: requires ADMIN_ALLOW_INLINE_TOKEN=1
  rate_limit:
    requests_per_minute: 30
```

### Environment Variables

| Variable                    | Description                       |
|-----------------------------|-----------------------------------|
| `ADMIN_ENABLED`             | Enable admin API (`true`/`1`)     |
| `ADMIN_ADDRESS`             | Admin listener address            |
| `ADMIN_TLS_ENABLED`         | Enable TLS for admin listener     |
| `ADMIN_TLS_CERT_FILE`       | TLS certificate file path         |
| `ADMIN_TLS_KEY_FILE`        | TLS key file path                 |
| `ADMIN_AUTH_TYPE`            | Auth type (only `bearer`)         |
| `ADMIN_AUTH_TOKEN_FILE`     | Path to bearer token file (0600)  |
| `ADMIN_AUTH_TOKEN`          | Inline bearer token (dev only)    |
| `ADMIN_ALLOW_INLINE_TOKEN`  | Set to `1` to allow inline tokens |
| `ADMIN_RATE_LIMIT_RPM`     | Max requests per minute           |

### Security Requirements

- Token file must have file mode `0600` or stricter
- Token must be at least 32 bytes (decoded from hex/base64, or 32 chars raw)
- Non-loopback addresses require TLS enabled
- Admin address must differ from data-plane listen address

## Authentication

All requests must include:

```
Authorization: Bearer <token>
```

Tokens are compared using `crypto/subtle.ConstantTimeCompare` to prevent
timing side-channels.

## Endpoints

### POST /admin/kms/rotate/start

Begin a key rotation by entering the drain phase.

**Request Body** (optional):

```json
{
  "target_version": 2,       // Optional: explicit target version
  "grace_period": "30s"      // Optional: max drain wait (default: 30s)
}
```

**Response** (202 Accepted):

```json
{
  "rotation_id": "rot-1713391200000-1-to-2",
  "phase": "draining",
  "current_version": 1,
  "target_version": 2,
  "grace_deadline": "2026-04-17T22:00:30Z",
  "provider": "memory"
}
```

**Errors**:
- `501` — Key manager doesn't support rotation
- `400` — Ambiguous target (supply `target_version`)
- `409` — Rotation already in progress

### GET /admin/kms/rotate/status

Poll the current rotation state.

**Response** (200 OK):

```json
{
  "rotation_id": "rot-1713391200000-1-to-2",
  "phase": "ready_for_cutover",
  "current_version": 1,
  "target_version": 2,
  "in_flight_wraps": 0,
  "started_at": "2026-04-17T22:00:00Z",
  "grace_deadline": "2026-04-17T22:00:30Z",
  "provider": "memory"
}
```

**Phases**: `idle`, `draining`, `ready_for_cutover`, `committing`,
`committed`, `aborted`

### POST /admin/kms/rotate/commit

Promote the target version as the new active wrapping key.

**Request Body** (optional):

```json
{
  "force": true    // Skip drain wait (use with caution)
}
```

**Response** (200 OK): Updated rotation snapshot

**Errors**:
- `409` — Not ready to commit (still draining with in-flight wraps)
- `500` — Promotion failed

### POST /admin/kms/rotate/abort

Cancel a pending rotation. Only valid from `draining` or
`ready_for_cutover` states.

**Response** (200 OK): Updated rotation snapshot showing `aborted` phase

## Example: Full Rotation Workflow

```bash
TOKEN="$(cat /etc/gateway/admin-token)"
ADMIN="http://127.0.0.1:8081"

# 1. Start rotation
curl -s -X POST "$ADMIN/admin/kms/rotate/start" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"grace_period": "30s"}'

# 2. Poll status until ready
while true; do
  STATUS=$(curl -s "$ADMIN/admin/kms/rotate/status" \
    -H "Authorization: Bearer $TOKEN")
  PHASE=$(echo "$STATUS" | jq -r .phase)
  echo "Phase: $PHASE, In-flight: $(echo "$STATUS" | jq .in_flight_wraps)"
  [ "$PHASE" = "ready_for_cutover" ] && break
  sleep 1
done

# 3. Commit
curl -s -X POST "$ADMIN/admin/kms/rotate/commit" \
  -H "Authorization: Bearer $TOKEN"
```

## Runtime Profiling Endpoints (V0.6-OBS-1)

Profiling endpoints are mounted when `admin.profiling.enabled: true`.
They inherit the same bearer-token auth and rate limiter as all other admin
endpoints. Every fetch emits an audit event (`event_type: pprof_fetch`).

| Endpoint | Description |
|---|---|
| `GET /admin/debug/pprof/` | Profile index (HTML) |
| `GET /admin/debug/pprof/cmdline` | Binary command line |
| `GET /admin/debug/pprof/profile?seconds=N` | CPU profile (default 30 s; capped by `max_profile_seconds`) |
| `GET /admin/debug/pprof/symbol` | Symbol lookup (POST body: hex address list) |
| `GET /admin/debug/pprof/trace?seconds=N` | Execution trace (capped by `max_profile_seconds`) |
| `GET /admin/debug/pprof/heap` | Heap allocation snapshot |
| `GET /admin/debug/pprof/goroutine` | Goroutine stack traces |
| `GET /admin/debug/pprof/allocs` | All past allocations |
| `GET /admin/debug/pprof/block` | Goroutine blocking events (requires `block_rate > 0`) |
| `GET /admin/debug/pprof/mutex` | Mutex contention (requires `mutex_fraction > 0`) |
| `GET /admin/debug/pprof/threadcreate` | Thread creation profile |

**Rate-limited responses:**

- `429 Too Many Requests` with `Retry-After: 1` when
  `max_concurrent_profiles` in-flight requests are already active.
- `400 Bad Request` when `?seconds=` is outside `[1, max_profile_seconds]`.

See `docs/OBSERVABILITY.md §"Runtime Profiling"` for operator recipes,
security model, and Grafana dashboard snippet.

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kms_active_key_version` | Gauge | `provider` | Active wrapping key version |
| `kms_rotation_operations_total` | Counter | `step`, `result` | Rotation operations count |
| `kms_rotation_duration_seconds` | Histogram | `step` | Rotation step duration |
| `kms_rotation_in_flight_wraps` | Gauge | — | In-flight WrapKey calls during drain |
| `gateway_admin_api_enabled` | Gauge | — | Whether admin API is active |
| `gateway_admin_profiling_enabled` | Gauge | — | Whether pprof routes are mounted (V0.6-OBS-1) |
| `s3_gateway_admin_pprof_requests_total` | Counter | `endpoint`, `outcome` | pprof fetches by endpoint and outcome (V0.6-OBS-1) |

## Audit Events

All rotation operations emit structured audit events via `LogAccessWithMetadata`:

- `key_rotation.start`
- `key_rotation.committed`
- `key_rotation.commit_failed`
- `key_rotation.aborted`
- `pprof_fetch` — emitted on every pprof endpoint access (V0.6-OBS-1)
