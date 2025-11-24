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

**Note on `useClientCredentials`**: When set to `"true"`, the gateway extracts credentials from client requests instead of using configured backend credentials. In this mode:
- `config.backend.accessKey` and `config.backend.secretKey` are **NOT required** and will be excluded from the deployment
- Clients must provide credentials in every request via **query parameters only** (`?AWSAccessKeyId=...&AWSSecretAccessKey=...`)
- **AWS Signature V4 (Authorization header) is NOT supported** - the signature includes the Host header, which prevents forwarding requests to the backend
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
| `config.encryption.keyManager.provider` | KMS provider: "cosmian" (supported), "aws", "vault" (planned) | `"cosmian"` |
| `config.encryption.keyManager.dualReadWindow` | Number of previous key versions to try during rotation | `"1"` |
| `config.encryption.keyManager.cosmian.endpoint` | Cosmian KMIP endpoint (JSON/HTTP recommended: `http://host:port/kmip/2_1` or binary: `host:port`) | `""` |
| `config.encryption.keyManager.cosmian.timeout` | KMS operation timeout | `"10s"` |
| `config.encryption.keyManager.cosmian.keys` | Comma-separated keys (format: "key1:1,key2:2") | `""` |
| `config.encryption.keyManager.cosmian.caCert` | CA certificate path for TLS (use valueFrom) | `""` |
| `config.encryption.keyManager.cosmian.clientCert` | Client certificate path for TLS (use valueFrom) | `""` |
| `config.encryption.keyManager.cosmian.clientKey` | Client key path for TLS (use valueFrom) | `""` |
| `config.encryption.keyManager.cosmian.insecureSkipVerify` | Skip TLS verification (testing only) | `"false"` |

**Key Manager (KMS) Configuration**: When `config.encryption.keyManager.enabled` is set to `"true"`, the gateway uses external KMS for envelope encryption. Currently, only **Cosmian KMIP** is fully supported.

**Protocol Selection**:
- **JSON/HTTP (Recommended)**: 
  - Full URL format (recommended): `http://host:9998/kmip/2_1`
  - Base URL format (also works): `http://host:9998` (path `/kmip/2_1` is automatically appended)
  - Fully tested and verified in CI
- **Binary KMIP (Advanced)**: Use `host:5696` format - requires proper TLS certificates (not fully tested in CI)

See the [KMS Compatibility Guide](../../docs/KMS_COMPATIBILITY.md) for details.

**Example KMS Configuration**:

```yaml
config:
  encryption:
    password:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: encryption-password
    keyManager:
      enabled:
        value: "true"
      provider:
        value: "cosmian"
      dualReadWindow:
        value: "1"
      cosmian:
        endpoint:
          # RECOMMENDED: JSON/HTTP endpoint (tested and verified)
          # Full URL format (recommended for clarity):
          value: "http://cosmian-kms:9998/kmip/2_1"
          # Base URL format (also works - path /kmip/2_1 is auto-appended):
          # value: "http://cosmian-kms:9998"
          # ADVANCED: Binary KMIP (requires TLS certificates: caCert, clientCert, clientKey)
          # value: "cosmian-kms:5696"
        timeout:
          value: "10s"
        keys:
          # Format: "key1:version1,key2:version2" (comma-separated)
          # Example: "wrapping-key-1:1" or "wrapping-key-1:1,wrapping-key-2:2" for rotation
          value: "wrapping-key-1:1"
        # TLS configuration
        # - For HTTP (testing): Not required
        # - For HTTPS (production): caCert recommended for server verification
        # - For binary KMIP: caCert, clientCert, clientKey all required (mutual TLS)
        caCert:
          valueFrom:
            secretKeyRef:
              name: cosmian-kms-certs
              key: ca-cert
        clientCert:
          valueFrom:
            secretKeyRef:
              name: cosmian-kms-certs
              key: client-cert
        clientKey:
          valueFrom:
            secretKeyRef:
              name: cosmian-kms-certs
              key: client-key
        insecureSkipVerify:
          value: "false"
```

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
| `config.tls.useCertManager` | Use cert-manager for automatic certificates | `"false"` |
| `config.tls.certFile` | TLS certificate file path (when not using cert-manager) | `""` |
| `config.tls.keyFile` | TLS key file path (when not using cert-manager) | `""` |

#### cert-manager Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `certManager.issuer.name` | Name for the issuer | `""` |
| `certManager.issuer.namespace` | Namespace for the issuer | `""` |
| `certManager.issuer.selfSigned` | Self-signed issuer configuration | `{}` |
| `certManager.issuer.clusterIssuer` | Use ClusterIssuer (alternative to selfSigned) | `""` |
| `certManager.certificate.extraDNSNames` | Additional DNS names for certificate | `[]` |
| `certManager.certificate.duration` | Certificate validity duration | `"2160h"` |
| `certManager.certificate.renewBefore` | Renew before expiry | `"720h"` |

**cert-manager Integration**: When `config.tls.useCertManager` is enabled, the chart automatically creates Issuer and Certificate resources. A self-signed certificate is created by default, but you can configure Let's Encrypt or other issuers. The TLS certificate and key files are automatically mounted into the pod.

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
| `config.audit.redactMetadataKeys` | Comma-separated list of metadata keys to redact | `""` |
| `config.audit.sink.type` | Sink type (stdout, file, http) | `"stdout"` |
| `config.audit.sink.endpoint` | HTTP sink endpoint (for type=http) | `""` |
| `config.audit.sink.filePath` | File path (for type=file) | `""` |
| `config.audit.sink.batchSize` | Max events per batch | `"100"` |
| `config.audit.sink.flushInterval` | Max time before flush | `"5s"` |
| `config.audit.sink.retryCount` | Retries for failed writes | `"3"` |
| `config.audit.sink.retryBackoff` | Initial retry backoff | `"1s"` |

#### Ingress Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable Ingress creation | `false` |
| `ingress.className` | Ingress class name | `""` |
| `ingress.annotations` | Additional ingress annotations | `{}` |
| `ingress.hosts` | List of ingress hosts and paths | `[]` |
| `ingress.tls` | TLS configuration for ingress | `[]` |

**Common Ingress Annotations**: The chart supports common ingress controller annotations. Some examples:
- `kubernetes.io/ingress.class: nginx`
- `cert-manager.io/cluster-issuer: letsencrypt-prod`
- `nginx.ingress.kubernetes.io/ssl-redirect: "true"`
- `nginx.ingress.kubernetes.io/proxy-body-size: "0"`
- `nginx.ingress.kubernetes.io/proxy-read-timeout: "600"`

**Note**: When `config.tls.enabled.value` is `true`, SSL redirect annotations are automatically added to force HTTPS traffic.

#### Deployment Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `kenchrcum/s3-encryption-gateway` |
| `image.tag` | Image tag | `"0.5.2"` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `imagePullSecrets` | Image pull secrets | `[]` |
| `podAnnotations` | Additional pod annotations | `{}` |
| `podSecurityContext` | Pod security context | See values.yaml |
| `securityContext` | Container security context | See values.yaml |
| `service.enabled` | Enable Service creation | `true` |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port (only used when TLS is disabled) | `80` |
| `service.targetPort` | Service target port | `8080` |

**Note**: When `config.tls.enabled.value` is `true`, the Service automatically uses port `443` with port name `https` instead of the configured `service.port`. This ensures proper HTTPS service discovery (e.g., `https://service-name.namespace.svc.cluster.local:443`).
| `resources` | Resource requests/limits | See values.yaml |
| `autoscaling.enabled` | Enable HPA | `false` |
| `podDisruptionBudget.enabled` | Enable PodDisruptionBudget | `false` |
| `podDisruptionBudget.minAvailable` | Minimum available pods during disruption | `""` |
| `podDisruptionBudget.maxUnavailable` | Maximum unavailable pods during disruption | `""` |
| `topologySpreadConstraints` | Pod topology spread constraints | `[]` |
| `nodeSelector` | Node selector labels | `{}` |
| `tolerations` | Pod tolerations | `[]` |
| `affinity` | Pod affinity/anti-affinity rules | `{}` |

#### Service Account

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create a ServiceAccount | `true` |
| `serviceAccount.name` | Use existing ServiceAccount name (when create=false uses this; when create=true overrides generated name) | `""` |

#### Monitoring

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceMonitor.enabled` | Enable ServiceMonitor (Prometheus Operator) | `false` |
| `serviceMonitor.interval` | Scrape interval | `30s` |
| `serviceMonitor.scrapeTimeout` | Scrape timeout | `10s` |
| `serviceMonitor.labels` | Additional ServiceMonitor labels | `{}` |
| `podMonitor.enabled` | Enable PodMonitor (Prometheus Operator) | `false` |
| `podMonitor.interval` | Scrape interval | `30s` |
| `podMonitor.scrapeTimeout` | Scrape timeout | `10s` |
| `podMonitor.labels` | Additional PodMonitor labels | `{}` |

**ServiceMonitor vs PodMonitor**: Both ServiceMonitor and PodMonitor provide Prometheus metrics collection but target different Kubernetes resources:
- **ServiceMonitor**: Targets the Service (recommended for most deployments)
- **PodMonitor**: Targets pods directly (useful when Service is disabled or for advanced pod-level metrics)

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

## Extending the Chart

The Helm chart supports several extension points to customize the deployment for advanced use cases.

### Extra Environment Variables

Add custom environment variables to the main container:

```yaml
extraEnv:
  - name: MY_CUSTOM_VAR
    value: "my-value"
  - name: MY_SECRET_VAR
    valueFrom:
      secretKeyRef:
        name: my-secret
        key: my-key
```

### Extra Volumes and Volume Mounts

Mount additional volumes into the main container:

```yaml
extraVolumes:
  - name: my-config
    configMap:
      name: my-configmap
  - name: my-secret-volume
    secret:
      secretName: my-secret

extraVolumeMounts:
  - name: my-config
    mountPath: /etc/my-config
    readOnly: true
  - name: my-secret-volume
    mountPath: /etc/my-secrets
    readOnly: true
```

### Init Containers

Run initialization containers before the main gateway starts:

```yaml
initContainers:
  - name: init-myservice
    image: busybox:1.35
    command: ['sh', '-c', 'echo "Initializing..." && sleep 5']
    volumeMounts:
      - name: shared-data
        mountPath: /data
    env:
      - name: INIT_VAR
        value: "initialized"
```

### Sidecar Containers

Run sidecar containers alongside the main gateway:

```yaml
sidecars:
  - name: sidecar-logger
    image: fluent/fluent-bit:2.0
    ports:
      - containerPort: 2020
    volumeMounts:
      - name: varlogcontainers
        mountPath: /var/log/containers
        readOnly: true
    env:
      - name: FLUENT_ELASTICSEARCH_HOST
        value: "elasticsearch.default.svc.cluster.local"
      - name: FLUENT_ELASTICSEARCH_PORT
        value: "9200"
```

### Complete Example with Extensions

```yaml
# Extra environment variables
extraEnv:
  - name: LOG_LEVEL
    value: "debug"
  - name: CUSTOM_CONFIG
    valueFrom:
      configMapKeyRef:
        name: my-gateway-config
        key: custom-setting

# Extra volumes and mounts
extraVolumes:
  - name: custom-config
    configMap:
      name: my-gateway-config
  - name: ssl-certs
    secret:
      secretName: my-ssl-certs

extraVolumeMounts:
  - name: custom-config
    mountPath: /etc/gateway-config
    readOnly: true
  - name: ssl-certs
    mountPath: /etc/ssl/certs
    readOnly: true

# Init container for setup
initContainers:
  - name: setup-gateway
    image: busybox:1.35
    command: ['sh', '-c', 'mkdir -p /tmp/setup && echo "Gateway setup complete" > /tmp/setup/done']
    volumeMounts:
      - name: setup-volume
        mountPath: /tmp/setup

# Sidecar for monitoring
sidecars:
  - name: prometheus-exporter
    image: nginx/nginx-prometheus-exporter:0.11.0
    ports:
      - containerPort: 9113
        name: http
    env:
      - name: SCRAPE_URI
        value: "http://localhost:8080/metrics"
```

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

### KMS Mode with Cosmian KMIP

Deploy the gateway with external KMS (Cosmian KMIP) for envelope encryption and key rotation:

```bash
# Create secrets for backend and encryption password
kubectl create secret generic s3-encryption-gateway-secrets \
  --from-literal=backend-access-key='YOUR_ACCESS_KEY' \
  --from-literal=backend-secret-key='YOUR_SECRET_KEY' \
  --from-literal=encryption-password='fallback-password-123456' \
  --from-literal=cosmian-kms-endpoint='cosmian-kms:5696' \
  --from-literal=cosmian-kms-keys='wrapping-key-1:1'

# If using TLS, also create certificate secrets
kubectl create secret generic cosmian-kms-certs \
  --from-file=ca-cert=/path/to/ca.pem \
  --from-file=client-cert=/path/to/client.crt \
  --from-file=client-key=/path/to/client.key
```

Deploy with KMS enabled:

```yaml
config:
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
    keyManager:
      enabled:
        value: "true"
      provider:
        value: "cosmian"
      dualReadWindow:
        value: "1"
      cosmian:
        endpoint:
          valueFrom:
            secretKeyRef:
              name: s3-encryption-gateway-secrets
              key: cosmian-kms-endpoint
        timeout:
          value: "10s"
        keys:
          valueFrom:
            secretKeyRef:
              name: s3-encryption-gateway-secrets
              key: cosmian-kms-keys
        # TLS configuration (optional, for production)
        caCert:
          valueFrom:
            secretKeyRef:
              name: cosmian-kms-certs
              key: ca-cert
        clientCert:
          valueFrom:
            secretKeyRef:
              name: cosmian-kms-certs
              key: client-cert
        clientKey:
          valueFrom:
            secretKeyRef:
              name: cosmian-kms-certs
              key: client-key
        insecureSkipVerify:
          value: "false"
```

**Notes:**
- The `encryption.password` is still required as a fallback for objects encrypted before KMS was enabled
- The `cosmian-kms-keys` format is: `"key1:version1,key2:version2"` (comma-separated)
- **JSON/HTTP endpoint (recommended)**: 
  - Full URL format (recommended): `http://cosmian-kms:9998/kmip/2_1`
  - Base URL format (also works): `http://cosmian-kms:9998` (path `/kmip/2_1` is automatically appended)
  - Fully tested and verified in CI
  - No TLS client certificates required for HTTP
  - TLS `caCert` recommended for HTTPS in production
- **Binary KMIP endpoint (advanced)**: Use `host:port` format (e.g., `cosmian-kms:5696`)
  - Requires proper TLS configuration: `caCert`, `clientCert`, `clientKey` (mutual TLS)
  - Not fully tested in CI - use with caution
- Health checks automatically verify KMS connectivity via the `/ready` endpoint

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

In this mode, clients must include credentials in requests via **query parameters only**:
- Query parameters: `?AWSAccessKeyId=...&AWSSecretAccessKey=...`

**Important**: AWS Signature V4 (Authorization header) is **NOT supported** when `useClientCredentials` is enabled. The signature includes the Host header, which prevents forwarding requests to the backend because the signature was created for the gateway's hostname, not the backend's.

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

### With Ingress

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: s3-gateway.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: s3-gateway-tls
      hosts:
        - s3-gateway.example.com
```

### With Pod Disruption Budget

```yaml
podDisruptionBudget:
  enabled: true
  minAvailable: 1
  # Alternative: maxUnavailable: 50%
```

### With Topology Spread Constraints

```yaml
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: s3-encryption-gateway
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: s3-encryption-gateway
```

### With PodMonitor (Alternative to ServiceMonitor)

```yaml
podMonitor:
  enabled: true
  interval: 30s
  scrapeTimeout: 10s
  labels:
    prometheus: kube-prometheus
```

### With cert-manager TLS

```yaml
config:
  tls:
    enabled: "true"
    useCertManager: "true"

certManager:
  issuer:
    name: s3-gateway-issuer
    selfSigned: {}
    # Or use Let's Encrypt:
    # clusterIssuer: letsencrypt-prod
  certificate:
    extraDNSNames:
      - s3-gateway.internal.example.com
    duration: "2160h"
    renewBefore: "720h"
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

