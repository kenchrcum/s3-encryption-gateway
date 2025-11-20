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

