package s3

import (
	"fmt"
	"net/url"
	"strings"
)

// ProviderConfig holds provider-specific configuration.
type ProviderConfig struct {
	Name                string
	DefaultEndpoint     string
	RequiresRegion      bool
	RequiresPathStyle   bool
	SupportedRegions    []string
	DefaultRegion       string
	EndpointTemplate    string // Template for endpoint construction
	ForcePathStyle      bool   // Force path-style addressing
	SkipSSLVerify       bool   // Skip SSL verification (for self-signed certs)
}

// KnownProviders contains configuration for known S3-compatible providers.
var KnownProviders = map[string]ProviderConfig{
	"aws": {
		Name:              "AWS S3",
		DefaultEndpoint:   "https://s3.amazonaws.com",
		RequiresRegion:    true,
		RequiresPathStyle: false,
		SupportedRegions: []string{
			"us-east-1", "us-east-2", "us-west-1", "us-west-2",
			"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
			"ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
			"ap-northeast-2", "sa-east-1", "ca-central-1",
		},
		DefaultRegion: "us-east-1",
	},
	
	"minio": {
		Name:              "MinIO",
		DefaultEndpoint:   "http://localhost:9000",
		RequiresRegion:    false,
		RequiresPathStyle: true,
		DefaultRegion:     "us-east-1",
	},
	
	"wasabi": {
		Name:              "Wasabi",
		DefaultEndpoint:   "https://s3.wasabisys.com",
		RequiresRegion:    true,
		RequiresPathStyle: false,
		SupportedRegions: []string{
			"us-east-1", "us-east-2", "us-west-1", "eu-central-1",
			"ap-northeast-1", "ap-northeast-2",
		},
		DefaultRegion: "us-east-1",
	},
	
	"hetzner": {
		Name:              "Hetzner Storage Box",
		DefaultEndpoint:   "https://your-storagebox.your-server.de",
		RequiresRegion:    false,
		RequiresPathStyle: true,
		DefaultRegion:     "nbg1", // Nuremberg
	},
	
	"digitalocean": {
		Name:              "DigitalOcean Spaces",
		DefaultEndpoint:   "https://nyc3.digitaloceanspaces.com",
		RequiresRegion:    true,
		RequiresPathStyle: false,
		SupportedRegions: []string{
			"nyc3", "ams3", "sgp1", "sfo3", "fra1", "blr1",
		},
		DefaultRegion: "nyc3",
		EndpointTemplate: "https://%s.digitaloceanspaces.com",
	},
	
	"backblaze": {
		Name:              "Backblaze B2",
		DefaultEndpoint:   "https://s3.us-west-000.backblazeb2.com",
		RequiresRegion:    true,
		RequiresPathStyle: true,
		SupportedRegions: []string{
			"us-west-000", "us-west-001", "us-west-002", "us-west-004",
			"eu-central-003",
		},
		DefaultRegion: "us-west-000",
		EndpointTemplate: "https://s3.%s.backblazeb2.com",
	},
	
	"cloudflare": {
		Name:              "Cloudflare R2",
		DefaultEndpoint:   "https://<account-id>.r2.cloudflarestorage.com",
		RequiresRegion:    false,
		RequiresPathStyle: false,
		DefaultRegion:     "auto",
	},
	
	"linode": {
		Name:              "Linode Object Storage",
		DefaultEndpoint:   "https://us-east-1.linodeobjects.com",
		RequiresRegion:    true,
		RequiresPathStyle: false,
		SupportedRegions: []string{
			"us-east-1", "eu-central-1", "ap-south-1",
		},
		DefaultRegion: "us-east-1",
		EndpointTemplate: "https://%s.linodeobjects.com",
	},
	
	"scaleway": {
		Name:              "Scaleway Object Storage",
		DefaultEndpoint:   "https://s3.fr-par.scw.cloud",
		RequiresRegion:    true,
		RequiresPathStyle: false,
		SupportedRegions: []string{
			"fr-par", "nl-ams", "pl-waw", "ap-sg",
		},
		DefaultRegion: "fr-par",
		EndpointTemplate: "https://s3.%s.scw.cloud",
	},
	
	"oracle": {
		Name:              "Oracle Cloud Infrastructure",
		DefaultEndpoint:   "https://objectstorage.us-ashburn-1.oraclecloud.com",
		RequiresRegion:    true,
		RequiresPathStyle: false,
		SupportedRegions: []string{
			"us-ashburn-1", "us-phoenix-1", "eu-frankfurt-1",
			"uk-london-1", "ap-sydney-1", "ap-tokyo-1",
		},
		DefaultRegion: "us-ashburn-1",
		EndpointTemplate: "https://objectstorage.%s.oraclecloud.com",
	},
	
	"idrive": {
		Name:              "IDrive e2",
		DefaultEndpoint:   "https://s3.us-west-2.idrivee2-29.com",
		RequiresRegion:    true,
		RequiresPathStyle: true,
		SupportedRegions: []string{
			"us-west-2", "us-east-1", "eu-west-1", "ap-south-1",
		},
		DefaultRegion: "us-west-2",
		EndpointTemplate: "https://s3.%s.idrivee2-29.com",
	},
}

// GetProviderConfig returns the configuration for a given provider.
func GetProviderConfig(provider string) (ProviderConfig, error) {
	if provider == "" {
		return ProviderConfig{}, fmt.Errorf("provider name is required")
	}
	
	providerLower := strings.ToLower(provider)
	config, ok := KnownProviders[providerLower]
	if !ok {
		return ProviderConfig{}, fmt.Errorf("unknown provider: %s (supported: %s)", 
			provider, strings.Join(getProviderNames(), ", "))
	}
	
	return config, nil
}

// ValidateProviderConfig validates and normalizes provider configuration.
func ValidateProviderConfig(endpoint, provider, region string) (string, string, error) {
	config, err := GetProviderConfig(provider)
	if err != nil {
		return "", "", err
	}
	
	// Use default endpoint if not provided
	if endpoint == "" {
		if config.EndpointTemplate != "" && region != "" {
			endpoint = fmt.Sprintf(config.EndpointTemplate, region)
		} else {
			endpoint = config.DefaultEndpoint
		}
	}
	
	// Normalize endpoint
	endpoint = normalizeEndpoint(endpoint)
	
	// Use default region if not provided (always use default if available, even if not strictly required)
	if region == "" && config.DefaultRegion != "" {
		region = config.DefaultRegion
	}
	
	return endpoint, region, nil
}

// normalizeEndpoint normalizes the endpoint URL.
func normalizeEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	
	// Add https:// if no scheme provided
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "https://" + endpoint
	}
	
	// Remove trailing slash
	endpoint = strings.TrimSuffix(endpoint, "/")
	
	return endpoint
}

// ValidateEndpoint validates that an endpoint URL is well-formed.
func ValidateEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}
	
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("endpoint must use http:// or https:// scheme")
	}
	
	if u.Host == "" {
		return fmt.Errorf("endpoint must include a hostname")
	}
	
	return nil
}

// getProviderNames returns a list of all supported provider names.
func getProviderNames() []string {
	names := make([]string, 0, len(KnownProviders))
	for name := range KnownProviders {
		names = append(names, name)
	}
	return names
}

// IsProviderSupported checks if a provider is supported.
func IsProviderSupported(provider string) bool {
	_, ok := KnownProviders[strings.ToLower(provider)]
	return ok
}

// GetProviderDefaultEndpoint returns the default endpoint for a provider.
func GetProviderDefaultEndpoint(provider string) (string, error) {
	config, err := GetProviderConfig(provider)
	if err != nil {
		return "", err
	}
	return config.DefaultEndpoint, nil
}

// RequiresPathStyleAddressing returns whether a provider requires path-style addressing.
func RequiresPathStyleAddressing(provider string) bool {
	config, err := GetProviderConfig(provider)
	if err != nil {
		return false // Default to virtual-hosted style
	}
	return config.RequiresPathStyle || config.ForcePathStyle
}
