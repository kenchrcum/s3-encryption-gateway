# Docker & Kubernetes Deployment Strategy

## Overview

The S3 Encryption Gateway is designed for containerized deployment in Kubernetes environments. This document outlines the containerization and orchestration strategy, including all Phase 4 production features.

## Docker Container Design

### Multi-Stage Build Strategy

#### Dockerfile Structure
```dockerfile
# Build stage
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o s3-encryption-gateway ./cmd/server

# Runtime stage
FROM alpine:3.20
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/
COPY --from=builder /app/s3-encryption-gateway .
USER gateway
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1
ENTRYPOINT ["./s3-encryption-gateway"]
```

### Image Optimization

#### Base Image Choice
- **Alpine Linux**: Small footprint (~5MB), security-focused
- **Distroless**: Even smaller, but harder to debug
- **Scratch**: Minimal, requires static linking

#### Size Optimization Techniques
- **Static linking**: `CGO_ENABLED=0` eliminates dynamic dependencies
- **Minimal base**: Alpine with only essential packages
- **Layer caching**: Order COPY commands for optimal caching
- **Multi-stage builds**: Separate build and runtime environments

#### Security Hardening
- **Non-root user**: Run as `gateway` user (UID 1000)
- **Minimal attack surface**: Remove unnecessary packages
- **Read-only filesystem**: Use read-only root filesystem where possible
- **Security scanning**: Integrate Trivy or similar scanners

## Kubernetes Deployment

### Core Deployment Manifest

The main deployment manifest is located at `k8s/deployment.yaml`. Apply it with:

```bash
kubectl apply -f k8s/deployment.yaml
```

#### Deployment Features
- **Replicas**: 2 (configurable)
- **Resource limits**: CPU 500m, Memory 256Mi
- **Health probes**: Liveness and readiness
- **Security**: Non-root user, read-only filesystem

### Service Definition

The service is included in `k8s/deployment.yaml`. It exposes the gateway on port 80 internally.

### Ingress Configuration

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: s3-encryption-gateway
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - s3-gateway.yourdomain.com
    secretName: s3-gateway-tls
  rules:
  - host: s3-gateway.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: s3-encryption-gateway
            port:
              number: 80
```

## Configuration Management

### ConfigMap for Application Config

The ConfigMap at `k8s/configmap.yaml` includes Phase 4 configuration options:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: s3-encryption-gateway-config
data:
  backend-endpoint: "https://s3.us-east-1.amazonaws.com"
  backend-region: "us-east-1"
  # Phase 4: Rate limiting
  rate-limit-enabled: "false"
  rate-limit-requests: "100"
  rate-limit-window: "60s"
  # Phase 4: Server timeouts
  server-read-timeout: "15s"
  server-write-timeout: "15s"
  server-idle-timeout: "60s"
  server-read-header-timeout: "10s"
```

### Secret for Sensitive Data

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: s3-gateway-secrets
type: Opaque
data:
  encryption-password: <base64-encoded-password>
  backend-access-key: <base64-encoded-key>
  backend-secret-key: <base64-encoded-secret>
```

### Environment Variables

**Core Configuration:**
- **LISTEN_ADDR**: Server bind address (default ":8080")
- **ENCRYPTION_PASSWORD**: Password for key derivation
- **ENCRYPTION_PREFERRED_ALGORITHM**: Preferred AEAD ("AES256-GCM" or "ChaCha20-Poly1305")
- **ENCRYPTION_SUPPORTED_ALGORITHMS**: Comma-separated list of allowed algorithms
- **BACKEND_ENDPOINT**: S3 backend endpoint URL
- **BACKEND_REGION**: AWS region for backend
- **BACKEND_ACCESS_KEY**: Backend S3 access key
- **BACKEND_SECRET_KEY**: Backend S3 secret key
- **LOG_LEVEL**: Logging verbosity (debug, info, warn, error)
- **COMPRESSION_ENABLED**: Enable/disable compression (default: false)
- **COMPRESSION_MIN_SIZE**: Minimum object size to compress in bytes (default: 1024)
- **COMPRESSION_ALGORITHM**: Compression algorithm (gzip, zstd, default: gzip)
- **COMPRESSION_LEVEL**: Compression level 1-9 (default: 6)
- **COMPRESSION_CONTENT_TYPES**: Comma-separated list of compressible content types/prefixes

**Cache:**
- **CACHE_ENABLED**: Enable in-memory cache (default: false)
- **CACHE_MAX_SIZE**: Max total cache size in bytes (default: 104857600)
- **CACHE_MAX_ITEMS**: Max number of items (default: 1000)
- **CACHE_DEFAULT_TTL**: Default TTL (e.g., "5m")

**Audit:**
- **AUDIT_ENABLED**: Enable audit logging (default: false)
- **AUDIT_MAX_EVENTS**: Max events to buffer in memory (default: 10000)

### Phase 4 Configuration Options

#### TLS Configuration
- **TLS_ENABLED**: Enable TLS/HTTPS (true/false, default: false)
- **TLS_CERT_FILE**: Path to TLS certificate file
- **TLS_KEY_FILE**: Path to TLS private key file

#### Rate Limiting (Phase 4)
- **RATE_LIMIT_ENABLED**: Enable rate limiting (true/false, default: false)
- **RATE_LIMIT_REQUESTS**: Maximum requests per window (default: 100)
- **RATE_LIMIT_WINDOW**: Time window for rate limiting (e.g., "60s", default: 60s)

#### Server Timeouts (Phase 4)
- **SERVER_READ_TIMEOUT**: Read timeout duration (default: 15s)
- **SERVER_WRITE_TIMEOUT**: Write timeout duration (default: 15s)
- **SERVER_IDLE_TIMEOUT**: Idle connection timeout (default: 60s)
- **SERVER_READ_HEADER_TIMEOUT**: Header read timeout (default: 10s)
- **SERVER_MAX_HEADER_BYTES**: Maximum header size in bytes (default: 1048576)

## Health Checks and Monitoring

### Health Endpoints
- **GET /health**: Liveness probe - basic health check
- **GET /ready**: Readiness probe - full dependency check
- **GET /metrics**: Prometheus metrics endpoint

### Prometheus Metrics (Phase 4)

The gateway exports comprehensive Prometheus metrics:

#### HTTP Metrics
- `http_requests_total` - Total HTTP requests (labels: method, path, status)
- `http_request_duration_seconds` - Request duration histogram
- `http_request_bytes_total` - Total bytes transferred

#### S3 Operation Metrics
- `s3_operations_total` - Total S3 operations (labels: operation, bucket)
- `s3_operation_duration_seconds` - S3 operation duration
- `s3_operation_errors_total` - S3 operation errors (labels: operation, bucket, error_type)

#### Encryption Metrics
- `encryption_operations_total` - Encryption/decryption operations (labels: operation)
- `encryption_duration_seconds` - Encryption duration histogram
- `encryption_bytes_total` - Total bytes encrypted/decrypted
- `encryption_errors_total` - Encryption errors (labels: operation, error_type)

#### System Metrics (Phase 4)
- `active_connections` - Current active HTTP connections (gauge)
- `goroutines_total` - Number of goroutines (gauge)
- `memory_alloc_bytes` - Memory allocated (gauge)
- `memory_sys_bytes` - System memory usage (gauge)

All metrics are automatically collected and updated every 5 seconds.

### Monitoring Integration (Phase 4)

Apply the ServiceMonitor manifest (`k8s/servicemonitor.yaml`) to enable Prometheus scraping:

```bash
kubectl apply -f k8s/servicemonitor.yaml
```

The ServiceMonitor automatically discovers the gateway service and scrapes metrics from `/metrics` endpoint every 30 seconds.

**ServiceMonitor Configuration:**
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: s3-encryption-gateway
spec:
  selector:
    matchLabels:
      app: s3-encryption-gateway
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
    scrapeTimeout: 10s
```

## Security Configuration

### Network Policies (Phase 4)

Apply the NetworkPolicy manifest (`k8s/networkpolicy.yaml`) for network isolation:

```bash
kubectl apply -f k8s/networkpolicy.yaml
```

This restricts:
- **Ingress**: Only from ingress controllers and Prometheus
- **Egress**: Only to S3 endpoints (HTTPS) and DNS

**NetworkPolicy Configuration:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: s3-encryption-gateway-netpol
spec:
  podSelector:
    matchLabels:
      app: s3-encryption-gateway
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - protocol: TCP
      port: 443  # HTTPS to S3
```

### Security Headers (Phase 4)

The gateway automatically sets security headers on all responses:
- `X-Frame-Options: DENY` - Prevents clickjacking
- `X-Content-Type-Options: nosniff` - Prevents MIME type sniffing
- `X-XSS-Protection: 1; mode=block` - Enables XSS protection
- `Strict-Transport-Security` - HSTS for TLS connections
- `Content-Security-Policy: default-src 'self'` - CSP protection
- `Referrer-Policy: strict-origin-when-cross-origin` - Referrer policy
- `Permissions-Policy` - Restricts browser features

These headers are automatically applied via middleware and require no configuration.

### Rate Limiting (Phase 4)

Rate limiting protects against abuse and DDoS attacks. Configure via ConfigMap or environment variables:

```yaml
# In ConfigMap
rate-limit-enabled: "true"
rate-limit-requests: "100"
rate-limit-window: "60s"
```

**Rate Limiting Features:**
- Token bucket algorithm
- Per-client (IP address) limiting
- Configurable limits and time windows
- Automatic cleanup of old entries
- Returns HTTP 429 (Too Many Requests) when limit exceeded

**Example Deployment Configuration:**
```yaml
env:
- name: RATE_LIMIT_ENABLED
  valueFrom:
    configMapKeyRef:
      name: s3-encryption-gateway-config
      key: rate-limit-enabled
- name: RATE_LIMIT_REQUESTS
  valueFrom:
    configMapKeyRef:
      name: s3-encryption-gateway-config
      key: rate-limit-requests
- name: RATE_LIMIT_WINDOW
  valueFrom:
    configMapKeyRef:
      name: s3-encryption-gateway-config
      key: rate-limit-window
```

### Pod Security Standards
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: s3-gateway-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  runAsUser:
    rule: MustRunAsNonRoot
  fsGroup:
    rule: MustRunAs
    ranges:
    - min: 65534
      max: 65534
  readOnlyRootFilesystem: true
  allowedCapabilities: []
```

### TLS Configuration

The gateway supports both external TLS termination (at ingress) and internal TLS termination.

#### Internal TLS (Phase 4)

The gateway can terminate TLS directly:

```yaml
# In ConfigMap or environment variables
TLS_ENABLED: "true"
TLS_CERT_FILE: "/etc/tls/tls.crt"
TLS_KEY_FILE: "/etc/tls/tls.key"
```

**Kubernetes Secret for TLS:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: s3-gateway-tls
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-cert>
  tls.key: <base64-encoded-key>
```

**Mount in Deployment:**
```yaml
volumeMounts:
- name: tls-certs
  mountPath: /etc/tls
  readOnly: true
volumes:
- name: tls-certs
  secret:
    secretName: s3-gateway-tls
```

#### External TLS (Ingress)

- **Certificate management**: cert-manager with Let's Encrypt
- **TLS versions**: TLS 1.2+ only
- Recommended for production (simpler certificate management)

## Resource Management

### Resource Requests and Limits
```yaml
resources:
  requests:
    memory: "128Mi"
    cpu: "100m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

### Horizontal Pod Autoscaling (Phase 4)

Apply the HPA manifest (`k8s/hpa.yaml`) for automatic scaling:

```bash
kubectl apply -f k8s/hpa.yaml
```

The HPA scales based on:
- **CPU utilization** (target: 70%)
- **Memory utilization** (target: 80%)
- **Min replicas**: 2
- **Max replicas**: 10

**HPA Configuration:**
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: s3-encryption-gateway
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: s3-encryption-gateway
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

**Scaling Behavior:**
- **Scale Up**: Aggressive (100% or +2 pods per 15s)
- **Scale Down**: Conservative (50% per 60s with 5min stabilization)

### Vertical Pod Autoscaling (Optional)
```yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: s3-gateway-vpa
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: s3-encryption-gateway
  updatePolicy:
    updateMode: "Auto"
```

## High Availability and Scaling

### Multi-AZ Deployment
```yaml
spec:
  topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        app: s3-encryption-gateway
```

### Rolling Updates
```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxUnavailable: 1
    maxSurge: 1
```

### Pod Disruption Budget
```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: s3-gateway-pdb
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: s3-encryption-gateway
```

## Logging and Observability

### Structured Logging
The gateway uses structured JSON logging with logrus. Logs include:
- Request ID tracking
- Operation context (bucket, key, operation)
- Error details
- Performance metrics

### Log Aggregation
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
data:
  fluent-bit.conf: |
    [INPUT]
        Name tail
        Path /var/log/containers/*s3-encryption-gateway*.log
        Parser docker

    [OUTPUT]
        Name es
        Host elasticsearch-master
        Port 9200
        Index s3-gateway
```

### Distributed Tracing
- **OpenTelemetry integration**: Add tracing spans for operations
- **Jaeger collector**: Collect and visualize traces
- **Trace sampling**: Configurable sampling rate

## Backup and Recovery

### Configuration Backup
- **GitOps**: Store manifests in Git repository
- **Config drift detection**: Tools like Config Syncer
- **Secret rotation**: Automated secret rotation procedures

### Data Recovery Considerations
- **Stateless design**: No local data storage
- **External dependencies**: S3 backend handles data persistence
- **Disaster recovery**: Multi-region backend configuration

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Build and Deploy
on:
  push:
    branches: [ main ]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Build Docker image
      run: |
        docker build -t s3-encryption-gateway:${{ github.sha }} .
    - name: Push to registry
      run: |
        docker push s3-encryption-gateway:${{ github.sha }}
    - name: Deploy to Kubernetes
      run: |
        kubectl set image deployment/s3-encryption-gateway \
          gateway=s3-encryption-gateway:${{ github.sha }}
```

## Quick Start Deployment

### Step 1: Create Secrets
```bash
kubectl create secret generic s3-encryption-gateway-secrets \
  --from-literal=backend-access-key=YOUR_KEY \
  --from-literal=backend-secret-key=YOUR_SECRET \
  --from-literal=encryption-password=YOUR_PASSWORD
```

### Step 2: Apply ConfigMap
```bash
kubectl apply -f k8s/configmap.yaml
```

### Step 3: Apply Deployment
```bash
kubectl apply -f k8s/deployment.yaml
```

### Step 4: Apply Phase 4 Resources (Optional but Recommended)
```bash
# ServiceMonitor for Prometheus
kubectl apply -f k8s/servicemonitor.yaml

# Horizontal Pod Autoscaler
kubectl apply -f k8s/hpa.yaml

# NetworkPolicy for security
kubectl apply -f k8s/networkpolicy.yaml
```

### Step 5: Verify Deployment
```bash
# Check pods
kubectl get pods -l app=s3-encryption-gateway

# Check logs
kubectl logs -f deployment/s3-encryption-gateway

# Check metrics endpoint
kubectl port-forward svc/s3-encryption-gateway 8080:80
curl http://localhost:8080/metrics
```

## Troubleshooting

### Common Issues

**Pod CrashLoopBackOff:**
- Check logs: `kubectl logs <pod-name>`
- Verify secrets are correctly configured
- Check resource limits

**Metrics not appearing:**
- Verify ServiceMonitor is applied
- Check Prometheus can reach the service
- Verify network policies allow monitoring namespace

**Rate limiting too aggressive:**
- Adjust `RATE_LIMIT_REQUESTS` in ConfigMap
- Increase `RATE_LIMIT_WINDOW`
- Check application logs for 429 errors

**TLS certificate errors:**
- Verify certificate format (PEM)
- Check file paths are correct
- Verify secret is mounted correctly

## Security Best Practices

1. **Use external TLS termination** (Ingress) for production
2. **Enable rate limiting** to prevent abuse
3. **Apply NetworkPolicy** for network isolation
4. **Use non-root user** (already configured)
5. **Rotate secrets regularly**
6. **Monitor security metrics** in Prometheus
7. **Perform security audits** (see `PHASE4_SECURITY_AUDIT.md`)

## Performance Tuning

### Resource Optimization
- Adjust CPU/memory limits based on workload
- Enable HPA for automatic scaling
- Monitor metrics for bottlenecks

### Network Optimization
- Use connection pooling for S3 backend
- Configure appropriate timeouts
- Enable compression for large objects

### Encryption Optimization
- Hardware acceleration (AES-NI) is automatically used when available
- Monitor encryption metrics for performance
- Consider compression for compressible data

## Additional Resources

- **Architecture**: See `ARCHITECTURE.md`
- **Development**: See `DEVELOPMENT_GUIDE.md`
- **Security Audit**: See `PHASE4_SECURITY_AUDIT.md`
- **API Implementation**: See `S3_API_IMPLEMENTATION.md`
