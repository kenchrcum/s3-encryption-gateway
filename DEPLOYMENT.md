# Docker & Kubernetes Deployment Strategy

## Overview

The S3 Encryption Gateway is designed for containerized deployment in Kubernetes environments. This document outlines the containerization and orchestration strategy.

## Docker Container Design

### Multi-Stage Build Strategy

#### Dockerfile Structure
```dockerfile
# Build stage
FROM golang:1.22-alpine AS builder
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
USER nobody
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
- **Non-root user**: Run as `nobody` or dedicated user
- **Minimal attack surface**: Remove unnecessary packages
- **Read-only filesystem**: Use read-only root filesystem where possible
- **Security scanning**: Integrate Trivy or similar scanners

### Image Metadata
```dockerfile
LABEL org.opencontainers.image.title="S3 Encryption Gateway"
LABEL org.opencontainers.image.description="Transparent S3 encryption proxy"
LABEL org.opencontainers.image.vendor="Your Organization"
LABEL org.opencontainers.image.version="v1.0.0"
LABEL org.opencontainers.image.created="2024-01-01T00:00:00Z"
```

## Kubernetes Deployment

### Core Deployment Manifest

#### Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: s3-encryption-gateway
  labels:
    app: s3-encryption-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: s3-encryption-gateway
  template:
    metadata:
      labels:
        app: s3-encryption-gateway
    spec:
      containers:
      - name: gateway
        image: your-registry/s3-encryption-gateway:v1.0.0
        ports:
        - containerPort: 8080
          name: http
        env:
        - name: LISTEN_ADDR
          value: ":8080"
        - name: ENCRYPTION_PASSWORD
          valueFrom:
            secretKeyRef:
              name: s3-gateway-secrets
              key: encryption-password
        - name: BACKEND_ENDPOINT
          valueFrom:
            configMapKeyRef:
              name: s3-gateway-config
              key: backend-endpoint
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: http
          initialDelaySeconds: 5
          periodSeconds: 5
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 65534
          capabilities:
            drop:
            - ALL
```

### Service Definition
```yaml
apiVersion: v1
kind: Service
metadata:
  name: s3-encryption-gateway
spec:
  selector:
    app: s3-encryption-gateway
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
  type: ClusterIP
```

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
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: s3-gateway-config
data:
  backend-endpoint: "https://s3.us-east-1.amazonaws.com"
  backend-region: "us-east-1"
  log-level: "info"
  max-connections: "100"
  request-timeout: "30s"
  compression-enabled: "false"  # Set to "true" to enable compression
  compression-min-size: "1024"  # Minimum object size to compress (bytes)
  compression-algorithm: "gzip" # gzip, zstd, etc.
  compression-level: "6"        # Compression level (1-9)
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
- **LISTEN_ADDR**: Server bind address (default ":8080")
- **ENCRYPTION_PASSWORD**: Password for key derivation
- **BACKEND_ENDPOINT**: S3 backend endpoint URL
- **BACKEND_REGION**: AWS region for backend
- **BACKEND_ACCESS_KEY**: Backend S3 access key
- **BACKEND_SECRET_KEY**: Backend S3 secret key
- **LOG_LEVEL**: Logging verbosity (debug, info, warn, error)
- **MAX_CONNECTIONS**: Maximum concurrent connections
- **REQUEST_TIMEOUT**: Request timeout duration
- **COMPRESSION_ENABLED**: Enable/disable compression (default: false)
- **COMPRESSION_MIN_SIZE**: Minimum object size to compress in bytes (default: 1024)
- **COMPRESSION_ALGORITHM**: Compression algorithm (gzip, zstd, default: gzip)
- **COMPRESSION_LEVEL**: Compression level 1-9 (default: 6)

## Health Checks and Monitoring

### Health Endpoints
- **GET /health**: Liveness probe - basic health check
- **GET /ready**: Readiness probe - full dependency check
- **GET /metrics**: Prometheus metrics endpoint

### Prometheus Metrics
```go
// Example metrics
var (
	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3_gateway_requests_total",
			Help: "Total number of S3 requests",
		},
		[]string{"method", "bucket", "status"},
	)

	encryptionDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "s3_gateway_encryption_duration_seconds",
			Help: "Time spent on encryption/decryption",
		},
		[]string{"operation"},
	)

	activeConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "s3_gateway_active_connections",
			Help: "Number of active connections",
		},
	)
)
```

### Monitoring Integration
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
```

## Security Configuration

### Network Policies
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: s3-gateway-netpol
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
- **External TLS**: Terminated at ingress level
- **Internal TLS**: Optional for service-to-service communication
- **Certificate management**: cert-manager with Let's Encrypt
- **TLS versions**: TLS 1.2+ only

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

### Horizontal Pod Autoscaling
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: s3-gateway-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: s3-encryption-gateway
  minReplicas: 3
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
```go
logger := logrus.New()
logger.SetFormatter(&logrus.JSONFormatter{
    TimestampFormat: time.RFC3339,
})
logger.SetLevel(logrus.InfoLevel)
```

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
      run: docker build -t s3-gateway:${{ github.sha }} .
    - name: Push to registry
      run: docker push your-registry/s3-gateway:${{ github.sha }}
    - name: Deploy to staging
      run: kubectl set image deployment/s3-gateway gateway=s3-gateway:${{ github.sha }} -n staging
```

### ArgoCD Integration
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: s3-encryption-gateway
spec:
  project: default
  source:
    repoURL: https://github.com/your-org/s3-encryption-gateway
    path: k8s
    targetRevision: HEAD
  destination:
    server: https://kubernetes.default.svc
    namespace: production
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

## Development and Testing

### Local Development
```yaml
# docker-compose.yml for local development
version: '3.8'
services:
  gateway:
    build: .
    ports:
      - "8080:8080"
    environment:
      - ENCRYPTION_PASSWORD=test-password
      - BACKEND_ENDPOINT=http://minio:9000
    depends_on:
      - minio

  minio:
    image: minio/minio
    ports:
      - "9000:9000"
    environment:
      - MINIO_ACCESS_KEY=test-key
      - MINIO_SECRET_KEY=test-secret
    command: server /data
```

### Testing Strategy
- **Unit tests**: Go test suite
- **Integration tests**: Test against MinIO
- **E2E tests**: Full deployment tests
- **Performance tests**: Load testing with k6

## Troubleshooting and Debugging

### Common Issues
- **Image pull failures**: Check registry credentials
- **Health check failures**: Verify endpoint responses
- **Encryption errors**: Check password configuration
- **Backend connectivity**: Verify network policies and DNS

### Debug Commands
```bash
# Check pod status
kubectl get pods -l app=s3-encryption-gateway

# View logs
kubectl logs -f deployment/s3-encryption-gateway

# Debug container
kubectl exec -it deployment/s3-encryption-gateway -- sh

# Check events
kubectl describe pod <pod-name>
```

This deployment strategy provides a production-ready setup for the S3 Encryption Gateway with security, scalability, and observability considerations.