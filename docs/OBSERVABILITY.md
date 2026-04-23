# Observability

The S3 Encryption Gateway provides comprehensive observability features including structured audit logging, Prometheus metrics, and OpenTelemetry distributed tracing.

## Audit Logging

Audit logging captures security-critical events such as encryption, decryption, key rotation, and access control decisions. These logs are essential for compliance and security auditing.

### Configuration

Audit logging is configured in the `audit` section of `config.yaml` or via environment variables.

```yaml
audit:
  enabled: true
  max_events: 10000
  sink:
    type: "file"
    file_path: "/var/log/s3-gateway/audit.json"
    batch_size: 100
    flush_interval: "5s"
  redact_metadata_keys: ["user_email", "ssn"]
```

### Log Sinks

The gateway supports multiple sink types for audit logs:

#### 1. Standard Output (`stdout`)
Default sink. Writes JSON-formatted events to standard output. Useful for containerized environments where logs are scraped by a sidecar or logging driver (e.g., Fluentd, Docker logging).

#### 2. File (`file`)
Writes JSON events to a specified file.
- **Configuration**: `file_path` (Required)
- **Behavior**: Appends to file. Does not handle rotation (use logrotate or similar external tools).

#### 3. HTTP/Webhook (`http`)
Sends batches of JSON events to an HTTP endpoint (POST). Compatible with Logstash, OpenSearch, Splunk HEC, or custom collectors.
- **Configuration**: 
  - `endpoint` (Required): Full URL
  - `headers`: Map of custom headers (e.g., Authorization)
- **Behavior**: Sends JSON array of events. Retries on failure with exponential backoff.

### Event Structure

Audit events are structured JSON objects:

```json
{
  "timestamp": "2023-10-27T10:00:00Z",
  "event_type": "encrypt",
  "operation": "encrypt",
  "bucket": "my-bucket",
  "key": "sensitive-data.txt",
  "algorithm": "AES256-GCM",
  "key_version": 1,
  "success": true,
  "duration_ms": 45,
  "metadata": {
    "content_type": "text/plain",
    "user_agent": "aws-cli/2.0"
  }
}
```

### Redaction

You can configure `redact_metadata_keys` to prevent sensitive metadata fields from being logged. Values for these keys will be replaced with `[REDACTED]`.

## Metrics

Prometheus metrics are exposed at `/metrics`.

### Key Metrics

- `s3_gateway_http_requests_total`: Total count of HTTP requests
- `s3_gateway_http_request_duration_seconds`: Latency distribution
- `s3_gateway_encryption_operations_total`: Count of crypto operations
- `s3_gateway_encryption_duration_seconds`: Crypto operation latency
- `s3_gateway_kms_rotated_reads_total`: Count of reads using non-active key versions

## Distributed Tracing

The gateway supports OpenTelemetry for distributed tracing.

### Configuration

```yaml
tracing:
  enabled: true
  service_name: "s3-encryption-gateway"
  exporter: "otlp"  # stdout, jaeger, otlp
  otlp_endpoint: "localhost:4317"
  sampling_ratio: 1.0
```

Sensitive data in traces is redacted by default (`redact_sensitive: true`).

## Runtime Profiling

The gateway ships optional pprof profiling endpoints on the **admin listener**
(`127.0.0.1:8081` by default). These endpoints are disabled by default and
require the admin subsystem to be enabled first.

> **Security model:** All pprof endpoints inherit the admin listener's
> bearer-token authentication, rate limiter, and (on non-loopback addresses)
> TLS requirement. Every profile fetch emits an audit event
> (`event_type: pprof_fetch`) and increments the
> `s3_gateway_admin_pprof_requests_total{endpoint,outcome}` counter.
> Per Adkins et al., *Building Secure and Reliable Systems* Ch. 15: debug
> surfaces must be authenticated, authorised, and audited.

### Configuration

```yaml
admin:
  enabled: true
  address: "127.0.0.1:8081"
  auth:
    type: "bearer"
    token_file: "/etc/s3-gateway/admin-token"
  rate_limit:
    requests_per_minute: 30
  profiling:
    enabled: true              # Mount /admin/debug/pprof/* (default: false)
    block_rate: 0              # 0 = disabled. See runtime.SetBlockProfileRate.
    mutex_fraction: 0          # 0 = disabled. See runtime.SetMutexProfileFraction.
    max_concurrent_profiles: 2 # Max in-flight /profile or /trace requests.
    max_profile_seconds: 60    # Cap on ?seconds= for /profile and /trace.
```

Environment variable equivalents:

| Variable | Default |
|---|---|
| `ADMIN_PROFILING_ENABLED` | `false` |
| `ADMIN_PROFILING_BLOCK_RATE` | `0` |
| `ADMIN_PROFILING_MUTEX_FRACTION` | `0` |
| `ADMIN_PROFILING_MAX_CONCURRENT` | `2` |
| `ADMIN_PROFILING_MAX_SECONDS` | `60` |

**Validation rules:**

- `admin.profiling.enabled: true` requires `admin.enabled: true`.
- On a non-loopback `admin.address`, `admin.tls.enabled: true` is required.
- `block_rate` and `mutex_fraction` must be `>= 0`.
- `max_profile_seconds` must be in `[1, 600]`.

### Available endpoints

| Path | Description |
|---|---|
| `/admin/debug/pprof/` | Profile index (HTML) |
| `/admin/debug/pprof/cmdline` | Binary command line |
| `/admin/debug/pprof/profile` | CPU profile (`?seconds=N`, default 30 s) |
| `/admin/debug/pprof/symbol` | Symbol lookup |
| `/admin/debug/pprof/trace` | Execution trace (`?seconds=N`) |
| `/admin/debug/pprof/heap` | Heap allocation snapshot |
| `/admin/debug/pprof/goroutine` | Goroutine stack traces |
| `/admin/debug/pprof/allocs` | All past allocations |
| `/admin/debug/pprof/block` | Goroutine blocking events (requires `block_rate > 0`) |
| `/admin/debug/pprof/mutex` | Mutex contention (requires `mutex_fraction > 0`) |
| `/admin/debug/pprof/threadcreate` | Thread creation |

### Operator recipes

#### Recipe 1 — CPU flamegraph (interactive)

```bash
# Capture a 30-second CPU profile and open the web UI:
go tool pprof -http=:0 http://localhost:8081/admin/debug/pprof/profile?seconds=30
# Add the admin bearer token via a reverse proxy or SSH tunnel in production.
```

With TLS and bearer auth:

```bash
PPROF_TOKEN=$(cat /etc/s3-gateway/admin-token)
go tool pprof -http=:0 \
  -tls_ca /etc/s3-gateway/admin-ca.crt \
  -tls_cert /etc/s3-gateway/admin-client.crt \
  -tls_key  /etc/s3-gateway/admin-client.key \
  "https://admin.internal:8081/admin/debug/pprof/profile?seconds=30&Authorization=Bearer+${PPROF_TOKEN}"
```

Practical alternative (airgapped environments):

```bash
# Download the profile and analyse locally:
curl -s -H "Authorization: Bearer $(cat /etc/s3-gateway/admin-token)" \
  "http://localhost:8081/admin/debug/pprof/profile?seconds=30" \
  -o cpu.pprof
go tool pprof -http=:0 cpu.pprof
```

#### Recipe 2 — Heap snapshot

```bash
curl -s -H "Authorization: Bearer $(cat /etc/s3-gateway/admin-token)" \
  http://localhost:8081/admin/debug/pprof/heap \
  -o heap.pprof
go tool pprof -http=:0 heap.pprof
```

#### Recipe 3 — Goroutine leak snapshot

```bash
curl -s -H "Authorization: Bearer $(cat /etc/s3-gateway/admin-token)" \
  "http://localhost:8081/admin/debug/pprof/goroutine?debug=2" \
  -o goroutines.txt
# Inspect goroutines.txt for unexpected blocking goroutines.
```

### Block and mutex profiling

Block and mutex profiling are **off by default** because they add a steady-state
overhead of ~1 % (block) and ~2–5 % (mutex) under contention. Enable them
only for targeted investigations:

```yaml
admin:
  profiling:
    enabled: true
    block_rate: 1       # Sample ALL blocking events (expensive; use 1000 for sampling)
    mutex_fraction: 10  # Sample 1/10 mutex contention events
```

Endpoints return empty profiles when the respective rate is 0.

### Symbolicated images for profiling

The production Dockerfile strips symbols (`-ldflags="-w -s"`) to reduce binary
size. pprof will show hex addresses instead of function names in stripped
binaries. To profile with full function names:

```bash
# Build a non-stripped image (larger, for profiling sessions only):
make profile-image

# The image is tagged with ":profile" suffix:
docker run -p 8080:8080 -p 8081:8081 kenchrcum/s3-encryption-gateway:dev-profile
```

The `STRIP_SYMBOLS=false` build-arg is also available directly:

```bash
docker build --build-arg STRIP_SYMBOLS=false -t my-gateway:debug .
```

### Grafana dashboard snippet

Add the following panel to your Grafana dashboard to track pprof activity:

```promql
sum by (endpoint, outcome) (
  rate(s3_gateway_admin_pprof_requests_total[5m])
)
```

