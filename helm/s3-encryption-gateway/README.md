# S3 Encryption Gateway Helm Chart

A Helm chart for deploying the S3 Encryption Gateway - a transparent proxy that provides client-side encryption for S3-compatible storage services.

## Description

The S3 Encryption Gateway sits between S3 clients and backend storage providers, encrypting/decrypting data transparently while maintaining full S3 API compatibility. This Helm chart simplifies deployment to Kubernetes clusters.

## Repository

This chart is available at: **https://kenchrcum.github.io/s3-encryption-gateway**

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- A backend S3-compatible storage service (AWS S3, MinIO, Wasabi, Hetzner, etc.)
- Secrets containing backend credentials and encryption password

## Installation

### Add the Helm repository

```bash
helm repo add s3-encryption-gateway https://kenchrcum.github.io/s3-encryption-gateway
helm repo update
```

### Install the chart

```bash
helm install my-gateway s3-encryption-gateway/s3-encryption-gateway \
  --set config.backend.accessKey.valueFrom.secretKeyRef.name=my-secrets \
  --set config.backend.accessKey.valueFrom.secretKeyRef.key=access-key \
  --set config.backend.secretKey.valueFrom.secretKeyRef.name=my-secrets \
  --set config.backend.secretKey.valueFrom.secretKeyRef.key=secret-key \
  --set config.encryption.password.valueFrom.secretKeyRef.name=my-secrets \
  --set config.encryption.password.valueFrom.secretKeyRef.key=encryption-password
```

## Configuration

All configuration options support two methods:

1. **Direct values**: Set a value directly in `values.yaml` or via `--set`
2. **valueFrom**: Reference values from existing Secrets or ConfigMaps

### Using valueFrom with Secrets

Most sensitive values should be stored in Kubernetes Secrets and referenced:

```yaml
config:
  backend:
    accessKey:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: backend-access-key
    secretKey:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: backend-secret-key
  encryption:
    password:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: encryption-password
```

### Using valueFrom with ConfigMaps

Non-sensitive configuration can be stored in ConfigMaps:

```yaml
config:
  backend:
    endpoint:
      valueFrom:
        configMapKeyRef:
          name: s3-encryption-gateway-config
          key: backend-endpoint
    region:
      valueFrom:
        configMapKeyRef:
          name: s3-encryption-gateway-config
          key: backend-region
```

### Configuration Options

#### Basic Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.listenAddr` | Listen address | `":8080"` |
| `config.logLevel` | Log level (debug, info, warn, error) | `"info"` |
| `config.proxiedBucket` | Single bucket proxy mode (optional) | `""` |

#### Backend Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.backend.endpoint` | S3 backend endpoint | `"https://s3.amazonaws.com"` |
| `config.backend.region` | S3 backend region | `"us-east-1"` |
| `config.backend.accessKey` | Backend access key (use valueFrom) | `""` |
| `config.backend.secretKey` | Backend secret key (use valueFrom) | `""` |
| `config.backend.provider` | Provider name (optional) | `""` |
| `config.backend.useSSL` | Use SSL for backend | `"true"` |
| `config.backend.usePathStyle` | Use path-style bucket addressing | `"false"` |
| `config.backend.useClientCredentials` | Use credentials from client requests | `"false"` |

**Note on `useClientCredentials`**: When set to `"true"`, the gateway extracts credentials from client requests (query parameters or Authorization header) instead of using configured backend credentials. In this mode:
- `config.backend.accessKey` and `config.backend.secretKey` are **NOT required** and will be excluded from the deployment
- Clients must provide credentials in every request
- Requests without valid credentials will fail with `AccessDenied`
- Useful for providers like Hetzner that don't support per-bucket access keys

#### Encryption Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.encryption.password` | Encryption password (use valueFrom) | `""` |
| `config.encryption.keyFile` | Path to encryption key file (optional) | `""` |
| `config.encryption.preferredAlgorithm` | Preferred algorithm (AES256-GCM, ChaCha20-Poly1305) | `"AES256-GCM"` |
| `config.encryption.supportedAlgorithms` | Comma-separated list of supported algorithms | `"AES256-GCM,ChaCha20-Poly1305"` |
| `config.encryption.keyManager.enabled` | Enable key manager/KMS mode | `"false"` |

#### Compression Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.compression.enabled` | Enable compression | `"false"` |
| `config.compression.minSize` | Minimum size to compress (bytes) | `"1024"` |
| `config.compression.contentTypes` | Comma-separated content types to compress | `"text/plain,application/json,application/xml"` |
| `config.compression.algorithm` | Compression algorithm | `"gzip"` |
| `config.compression.level` | Compression level (1-9) | `"6"` |

#### Server Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.server.readTimeout` | Read timeout | `"15s"` |
| `config.server.writeTimeout` | Write timeout | `"15s"` |
| `config.server.idleTimeout` | Idle timeout | `"60s"` |
| `config.server.readHeaderTimeout` | Read header timeout | `"10s"` |
| `config.server.maxHeaderBytes` | Maximum header bytes | `"1048576"` |

#### TLS Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.tls.enabled` | Enable TLS | `"false"` |
| `config.tls.certFile` | TLS certificate file path | `""` |
| `config.tls.keyFile` | TLS key file path | `""` |

#### Rate Limiting

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.rateLimit.enabled` | Enable rate limiting | `"false"` |
| `config.rateLimit.limit` | Requests per window | `"100"` |
| `config.rateLimit.window` | Time window | `"60s"` |

#### Cache Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.cache.enabled` | Enable cache | `"false"` |
| `config.cache.maxSize` | Maximum cache size (bytes) | `"104857600"` |
| `config.cache.maxItems` | Maximum cache items | `"1000"` |
| `config.cache.defaultTTL` | Default TTL | `"5m"` |

#### Audit Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.audit.enabled` | Enable audit logging | `"false"` |
| `config.audit.maxEvents` | Maximum audit events | `"10000"` |

#### Deployment Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `kenchrcum/s3-encryption-gateway` |
| `image.tag` | Image tag | `"0.3.5"` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `service.enabled` | Enable Service creation | `true` |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `80` |
| `service.targetPort` | Service target port | `8080` |
| `resources` | Resource requests/limits | See values.yaml |
| `autoscaling.enabled` | Enable HPA | `false` |
| `serviceMonitor.enabled` | Enable ServiceMonitor | `false` |

#### Service Account

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create a ServiceAccount | `true` |
| `serviceAccount.name` | Use existing ServiceAccount name (when create=false uses this; when create=true overrides generated name) | `""` |

#### Network Policy

| Parameter | Description | Default |
|-----------|-------------|---------|
| `networkPolicy.enabled` | Create a NetworkPolicy | `false` |
| `networkPolicy.policyTypes` | List of policy types | `[Ingress, Egress]` |
| `networkPolicy.namespaceIsolation` | Restrict ingress to same namespace only | `true` |
| `networkPolicy.namespaceLabel.key` | Namespace label key for isolation | `"kubernetes.io/metadata.name"` |

**Namespace Isolation**: When `namespaceIsolation` is enabled (default), the NetworkPolicy restricts ingress traffic to only allow pods in the same namespace to access the gateway. This is useful for namespace-scoped deployments where you want to prevent cross-namespace access.

**Note**: Namespace isolation requires the namespace to have a label matching the configured `namespaceLabel.key`. Most modern Kubernetes distributions automatically label namespaces with `kubernetes.io/metadata.name`. If your namespace doesn't have this label, you can either:
1. Label your namespace: `kubectl label namespace <name> kubernetes.io/metadata.name=<name>`
2. Or configure a custom label key in `networkPolicy.namespaceLabel.key`

## Examples

### Basic Installation with Secrets

```bash
# Create secrets first
kubectl create secret generic s3-encryption-gateway-secrets \
  --from-literal=backend-access-key='YOUR_ACCESS_KEY' \
  --from-literal=backend-secret-key='YOUR_SECRET_KEY' \
  --from-literal=encryption-password='YOUR_ENCRYPTION_PASSWORD'

# Install with secrets
helm install my-gateway s3-encryption-gateway/s3-encryption-gateway \
  --namespace default
```

### Single Bucket Proxy Mode

Enable single bucket proxy to minimize IAM policy requirements:

```yaml
config:
  proxiedBucket:
    value: "my-secure-bucket"
  backend:
    endpoint:
      value: "https://s3.amazonaws.com"
    region:
      value: "us-east-1"
    accessKey:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: backend-access-key
    secretKey:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: backend-secret-key
  encryption:
    password:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: encryption-password
```

### Client Credentials Mode

Enable credential passthrough to use client-provided credentials (e.g., for Hetzner):

```yaml
config:
  proxiedBucket:
    value: "my-bucket"  # Still useful to restrict to single bucket
  backend:
    endpoint:
      value: "https://your-bucket.your-region.your-objectstorage.com"
    region:
      value: "nbg1"
    useClientCredentials:
      value: "true"
    # accessKey and secretKey are NOT required when useClientCredentials is true
  encryption:
    password:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: encryption-password
```

In this mode, clients must include credentials in requests:
- Query parameters: `?AWSAccessKeyId=...&AWSSecretAccessKey=...`
- Or via Authorization header (Signature V4)

Requests without valid credentials will be rejected with `AccessDenied`.

### Custom Configuration with ConfigMap

```yaml
# Create ConfigMap for non-sensitive config
apiVersion: v1
kind: ConfigMap
metadata:
  name: s3-gateway-config
data:
  backend-endpoint: "https://s3.wasabisys.com"
  backend-region: "us-east-1"
  rate-limit-enabled: "true"
  rate-limit-requests: "200"
  rate-limit-window: "60s"
---
# values.yaml
config:
  backend:
    endpoint:
      valueFrom:
        configMapKeyRef:
          name: s3-gateway-config
          key: backend-endpoint
    region:
      valueFrom:
        configMapKeyRef:
          name: s3-gateway-config
          key: backend-region
  rateLimit:
    enabled:
      valueFrom:
        configMapKeyRef:
          name: s3-gateway-config
          key: rate-limit-enabled
    limit:
      valueFrom:
        configMapKeyRef:
          name: s3-gateway-config
          key: rate-limit-requests
    window:
      valueFrom:
        configMapKeyRef:
          name: s3-gateway-config
          key: rate-limit-window
```

### With Autoscaling

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
```

### With Prometheus Monitoring

```yaml
serviceMonitor:
  enabled: true
  interval: 30s
  scrapeTimeout: 10s
  labels:
    prometheus: kube-prometheus
```

### Without Service

When using alternative ingress methods (like Ingress controllers) that handle service discovery, you can disable the Service:

```yaml
service:
  enabled: false
```

**Note**: When `service.enabled` is `false`, the ServiceMonitor will also be disabled automatically, as it requires a Service to function.

**Important**: For namespace-scoped deployments where pods need to communicate with the gateway, you should **keep the Service enabled** to provide stable DNS resolution**, as pod IPs can change over time. The NetworkPolicy with namespace isolation will still restrict access to the same namespace while allowing DNS-based service discovery.

### With Namespace Isolation

For namespace-scoped deployments with strict network isolation:

```yaml
service:
  enabled: true  # Keep Service enabled for DNS resolution (required for pod IP changes)

networkPolicy:
  enabled: true
  namespaceIsolation: true  # Restrict ingress to same namespace only
  namespaceLabel:
    key: "kubernetes.io/metadata.name"  # Standard Kubernetes namespace label
```

This configuration:
- **Keeps the Service enabled** - DNS resolution is essential because pod IPs can change during the gateway's lifetime (restarts, rescheduling, scaling). The Service provides a stable DNS name that resolves to the current pod IPs.
- Enables NetworkPolicy with namespace isolation
- Only allows pods in the same namespace to access the gateway via the Service
- Blocks cross-namespace communication while maintaining DNS-based service discovery

## Upgrading

```bash
helm repo update
helm upgrade my-gateway s3-encryption-gateway/s3-encryption-gateway
```

## Uninstalling

```bash
helm uninstall my-gateway
```

## Security Best Practices

1. **Use Secrets for Sensitive Data**: Always use `valueFrom.secretKeyRef` for:
   - Backend access keys and secret keys
   - Encryption passwords
   - TLS certificates and keys

2. **RBAC**: The chart creates a ServiceAccount. Configure RBAC as needed.

3. **Network Policies**: Enable network policies for additional security:
   ```yaml
   networkPolicy:
     enabled: true
     namespaceIsolation: true  # Restrict to same namespace (default)
   ```
   
   When `namespaceIsolation` is enabled, only pods in the same namespace can access the gateway, preventing cross-namespace communication. This is particularly useful for namespace-scoped deployments.

4. **Single Bucket Proxy**: Use `proxiedBucket` to restrict access to a single bucket, minimizing IAM policy requirements.

## Troubleshooting

### Check Pod Logs

```bash
kubectl logs -l app.kubernetes.io/name=s3-encryption-gateway
```

### Check Pod Status

```bash
kubectl get pods -l app.kubernetes.io/name=s3-encryption-gateway
```

### Test Health Endpoint

If the Service is enabled:
```bash
kubectl port-forward svc/s3-encryption-gateway 8080:80
curl http://localhost:8080/health
```

If the Service is disabled, port-forward directly to a pod:
```bash
kubectl port-forward <pod-name> 8080:8080
curl http://localhost:8080/health
```

## Support

For issues, feature requests, or questions:
- GitHub: https://github.com/kenneth/s3-encryption-gateway
- Chart Repository: https://kenchrcum.github.io/s3-encryption-gateway

## License

MIT License - see the main project repository [LICENSE](https://github.com/kenneth/s3-encryption-gateway/blob/main/LICENSE) file for details.

