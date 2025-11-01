# S3 Provider Support

This document lists all supported S3-compatible storage providers and their configuration requirements.

## Currently Supported Providers

### Previously Supported (Generic Support)
- ? **AWS S3** - Amazon Web Services S3
- ? **MinIO** - Self-hosted S3-compatible object storage
- ? **Wasabi** - Cloud storage provider
- ? **Hetzner** - Hetzner Storage Box

### Newly Added with Explicit Support
- ? **DigitalOcean Spaces** - DigitalOcean object storage
- ? **Backblaze B2** - Backblaze cloud storage
- ? **Cloudflare R2** - Cloudflare object storage
- ? **Linode Object Storage** - Linode object storage
- ? **Scaleway Object Storage** - Scaleway object storage
- ? **Oracle Cloud Infrastructure** - Oracle OCI Object Storage
- ? **IDrive e2** - IDrive cloud storage

## Provider Configurations

### AWS S3
```yaml
backend:
  provider: "aws"
  endpoint: ""  # Optional, defaults to s3.amazonaws.com
  region: "us-east-1"  # Required
```

**Regions**: us-east-1, us-east-2, us-west-1, us-west-2, eu-west-1, eu-west-2, eu-west-3, eu-central-1, ap-southeast-1, ap-southeast-2, ap-northeast-1, ap-northeast-2, sa-east-1, ca-central-1

### MinIO
```yaml
backend:
  provider: "minio"
  endpoint: "http://localhost:9000"  # Required - your MinIO server
  region: ""  # Optional, defaults to us-east-1
```

**Note**: MinIO uses path-style addressing by default.

### Wasabi
```yaml
backend:
  provider: "wasabi"
  endpoint: ""  # Optional, defaults to s3.wasabisys.com
  region: "us-east-1"  # Required
```

**Regions**: us-east-1, us-east-2, us-west-1, eu-central-1, ap-northeast-1, ap-northeast-2

### Hetzner Storage Box
```yaml
backend:
  provider: "hetzner"
  endpoint: "https://your-storagebox.your-server.de"  # Required
  region: ""  # Optional
```

**Note**: Hetzner uses path-style addressing.

### DigitalOcean Spaces
```yaml
backend:
  provider: "digitalocean"
  endpoint: ""  # Optional, auto-generated from region
  region: "nyc3"  # Required
```

**Regions**: nyc3, ams3, sgp1, sfo3, fra1, blr1

**Endpoint**: Automatically constructed as `https://<region>.digitaloceanspaces.com`

### Backblaze B2
```yaml
backend:
  provider: "backblaze"
  endpoint: ""  # Optional, auto-generated from region
  region: "us-west-000"  # Required
```

**Regions**: us-west-000, us-west-001, us-west-002, us-west-004, eu-central-003

**Endpoint**: Automatically constructed as `https://s3.<region>.backblazeb2.com`

**Note**: Backblaze requires path-style addressing.

### Cloudflare R2
```yaml
backend:
  provider: "cloudflare"
  endpoint: "https://<account-id>.r2.cloudflarestorage.com"  # Required
  region: ""  # Optional, defaults to "auto"
```

**Note**: Replace `<account-id>` with your Cloudflare account ID.

### Linode Object Storage
```yaml
backend:
  provider: "linode"
  endpoint: ""  # Optional, auto-generated from region
  region: "us-east-1"  # Required
```

**Regions**: us-east-1, eu-central-1, ap-south-1

**Endpoint**: Automatically constructed as `https://<region>.linodeobjects.com`

### Scaleway Object Storage
```yaml
backend:
  provider: "scaleway"
  endpoint: ""  # Optional, auto-generated from region
  region: "fr-par"  # Required
```

**Regions**: fr-par, nl-ams, pl-waw, ap-sg

**Endpoint**: Automatically constructed as `https://s3.<region>.scw.cloud`

### Oracle Cloud Infrastructure
```yaml
backend:
  provider: "oracle"
  endpoint: ""  # Optional, auto-generated from region
  region: "us-ashburn-1"  # Required
```

**Regions**: us-ashburn-1, us-phoenix-1, eu-frankfurt-1, uk-london-1, ap-sydney-1, ap-tokyo-1

**Endpoint**: Automatically constructed as `https://objectstorage.<region>.oraclecloud.com`

### IDrive e2
```yaml
backend:
  provider: "idrive"
  endpoint: ""  # Optional, auto-generated from region
  region: "us-west-2"  # Required
```

**Regions**: us-west-2, us-east-1, eu-west-1, ap-south-1

**Endpoint**: Automatically constructed as `https://s3.<region>.idrivee2-29.com`

**Note**: IDrive e2 requires path-style addressing.

## Features by Provider

| Provider | Path-Style Required | Region Required | Endpoint Template | Notes |
|----------|---------------------|-----------------|-------------------|-------|
| AWS S3 | ? | ? | No | Default provider |
| MinIO | ? | ? | No | Self-hosted |
| Wasabi | ? | ? | No | Cost-effective alternative |
| Hetzner | ? | ? | No | European provider |
| DigitalOcean | ? | ? | Yes | Simple Spaces API |
| Backblaze | ? | ? | Yes | Very cost-effective |
| Cloudflare | ? | ? | No | egress-free |
| Linode | ? | ? | Yes | Simple object storage |
| Scaleway | ? | ? | Yes | European provider |
| Oracle | ? | ? | Yes | Enterprise-grade |
| IDrive | ? | ? | Yes | Backup-focused |

## Provider-Specific Features

### Automatic Endpoint Generation
Providers with endpoint templates automatically generate endpoints from the region:
- DigitalOcean: `https://<region>.digitaloceanspaces.com`
- Backblaze: `https://s3.<region>.backblazeb2.com`
- Linode: `https://<region>.linodeobjects.com`
- Scaleway: `https://s3.<region>.scw.cloud`
- Oracle: `https://objectstorage.<region>.oraclecloud.com`
- IDrive: `https://s3.<region>.idrivee2-29.com`

### Path-Style Addressing
Some providers require path-style addressing (`bucket.s3.amazonaws.com` vs `s3.amazonaws.com/bucket`):
- MinIO (always)
- Hetzner (always)
- Backblaze (always)
- IDrive e2 (always)

The gateway automatically configures this based on provider settings.

## Configuration Examples

### Using DigitalOcean Spaces
```yaml
backend:
  provider: "digitalocean"
  endpoint: ""  # Will be auto-generated as https://nyc3.digitaloceanspaces.com
  region: "nyc3"
  access_key: "your-spaces-key"
  secret_key: "your-spaces-secret"
```

### Using Backblaze B2
```yaml
backend:
  provider: "backblaze"
  endpoint: ""  # Will be auto-generated as https://s3.us-west-000.backblazeb2.com
  region: "us-west-000"
  access_key: "your-key-id"
  secret_key: "your-application-key"
```

### Using Cloudflare R2
```yaml
backend:
  provider: "cloudflare"
  endpoint: "https://abc123def456.r2.cloudflarestorage.com"  # Replace with your account ID
  region: ""  # Not required for R2
  access_key: "your-r2-access-key"
  secret_key: "your-r2-secret-key"
```

## Environment Variables

All providers can be configured via environment variables:

```bash
export BACKEND_PROVIDER="digitalocean"
export BACKEND_ENDPOINT=""  # Optional
export BACKEND_REGION="nyc3"
export BACKEND_ACCESS_KEY="your-key"
export BACKEND_SECRET_KEY="your-secret"
```

## Adding New Providers

To add support for a new provider:

1. Add provider configuration to `internal/s3/providers.go` in `KnownProviders`
2. Set appropriate flags:
   - `RequiresRegion`: Whether region is mandatory
   - `RequiresPathStyle`: Whether path-style addressing is required
   - `EndpointTemplate`: Template for auto-generating endpoints
3. Add tests in `internal/s3/providers_test.go`
4. Update this documentation

## Testing

Provider configurations are tested automatically. Run:

```bash
go test ./internal/s3/... -v
```

## Notes

- All providers use the same AWS SDK v2 client under the hood
- Provider-specific configurations are handled automatically
- Endpoint validation ensures URLs are properly formatted
- Region defaults are applied when not specified
- Path-style addressing is configured automatically when required
