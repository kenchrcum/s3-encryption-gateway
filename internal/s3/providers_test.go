package s3

import (
	"testing"
)

func TestGetProviderConfig(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wantErr  bool
		check    func(*testing.T, ProviderConfig)
	}{
		{
			name:     "AWS provider",
			provider: "aws",
			wantErr:  false,
			check: func(t *testing.T, config ProviderConfig) {
				if config.Name != "AWS S3" {
					t.Errorf("expected name 'AWS S3', got %s", config.Name)
				}
				if !config.RequiresRegion {
					t.Error("AWS should require region")
				}
			},
		},
		{
			name:     "MinIO provider",
			provider: "minio",
			wantErr:  false,
			check: func(t *testing.T, config ProviderConfig) {
				if config.Name != "MinIO" {
					t.Errorf("expected name 'MinIO', got %s", config.Name)
				}
				if !config.RequiresPathStyle {
					t.Error("MinIO should require path-style addressing")
				}
			},
		},
		{
			name:     "Unknown provider",
			provider: "unknown",
			wantErr:  true,
		},
		{
			name:     "Case insensitive",
			provider: "AWS",
			wantErr:  false,
		},
		{
			name:     "DigitalOcean provider",
			provider: "digitalocean",
			wantErr:  false,
			check: func(t *testing.T, config ProviderConfig) {
				if config.Name != "DigitalOcean Spaces" {
					t.Errorf("expected name 'DigitalOcean Spaces', got %s", config.Name)
				}
				if config.DefaultRegion != "nyc3" {
					t.Errorf("expected default region 'nyc3', got %s", config.DefaultRegion)
				}
			},
		},
		{
			name:     "Backblaze provider",
			provider: "backblaze",
			wantErr:  false,
			check: func(t *testing.T, config ProviderConfig) {
				if config.Name != "Backblaze B2" {
					t.Errorf("expected name 'Backblaze B2', got %s", config.Name)
				}
				if !config.RequiresPathStyle {
					t.Error("Backblaze should require path-style addressing")
				}
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := GetProviderConfig(tt.provider)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			
			if tt.check != nil {
				tt.check(t, config)
			}
		})
	}
}

func TestValidateProviderConfig(t *testing.T) {
	tests := []struct {
		name          string
		endpoint      string
		provider      string
		region        string
		wantErr       bool
		checkEndpoint  string
		checkRegion   string
	}{
		{
			name:         "AWS with endpoint",
			endpoint:     "https://s3.us-west-2.amazonaws.com",
			provider:     "aws",
			region:       "us-west-2",
			wantErr:      false,
			checkEndpoint: "https://s3.us-west-2.amazonaws.com",
			checkRegion:  "us-west-2",
		},
		{
			name:         "AWS without endpoint, uses default",
			endpoint:     "",
			provider:     "aws",
			region:       "us-east-1",
			wantErr:      false,
			checkEndpoint: "https://s3.amazonaws.com",
			checkRegion:  "us-east-1",
		},
		{
			name:         "AWS without region, uses default",
			endpoint:     "",
			provider:     "aws",
			region:       "",
			wantErr:      false,
			checkRegion:  "us-east-1",
		},
		{
			name:         "DigitalOcean with template",
			endpoint:     "",
			provider:     "digitalocean",
			region:       "nyc3",
			wantErr:      false,
			checkEndpoint: "https://nyc3.digitaloceanspaces.com",
			checkRegion:  "nyc3",
		},
		{
			name:         "MinIO without region",
			endpoint:     "http://localhost:9000",
			provider:     "minio",
			region:       "",
			wantErr:      false,
			checkEndpoint: "http://localhost:9000",
			checkRegion:  "us-east-1",
		},
		{
			name:     "Unknown provider",
			endpoint:  "",
			provider:  "unknown",
			region:    "",
			wantErr:   true,
		},
		{
			name:         "Endpoint normalization - add https",
			endpoint:     "s3.amazonaws.com",
			provider:     "aws",
			region:       "us-east-1",
			wantErr:      false,
			checkEndpoint: "https://s3.amazonaws.com",
		},
		{
			name:         "Endpoint normalization - remove trailing slash",
			endpoint:     "https://s3.amazonaws.com/",
			provider:     "aws",
			region:       "us-east-1",
			wantErr:      false,
			checkEndpoint: "https://s3.amazonaws.com",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint, region, err := ValidateProviderConfig(tt.endpoint, tt.provider, tt.region)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			
			if tt.checkEndpoint != "" && endpoint != tt.checkEndpoint {
				t.Errorf("expected endpoint %s, got %s", tt.checkEndpoint, endpoint)
			}
			
			if tt.checkRegion != "" && region != tt.checkRegion {
				t.Errorf("expected region %s, got %s", tt.checkRegion, region)
			}
		})
	}
}

func TestValidateEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		endpoint string
		wantErr bool
	}{
		{
			name:     "Valid HTTPS endpoint",
			endpoint: "https://s3.amazonaws.com",
			wantErr:  false,
		},
		{
			name:     "Valid HTTP endpoint",
			endpoint: "http://localhost:9000",
			wantErr:  false,
		},
		{
			name:     "Invalid scheme",
			endpoint: "ftp://example.com",
			wantErr:  true,
		},
		{
			name:     "No hostname",
			endpoint: "https://",
			wantErr:  true,
		},
		{
			name:     "Invalid URL",
			endpoint: "not a url",
			wantErr:  true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEndpoint(tt.endpoint)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestIsProviderSupported(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		want     bool
	}{
		{"AWS", "aws", true},
		{"AWS uppercase", "AWS", true},
		{"MinIO", "minio", true},
		{"DigitalOcean", "digitalocean", true},
		{"Unknown", "unknown", false},
		{"Empty", "", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsProviderSupported(tt.provider)
			if got != tt.want {
				t.Errorf("IsProviderSupported(%q) = %v, want %v", tt.provider, got, tt.want)
			}
		})
	}
}

func TestRequiresPathStyleAddressing(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		want     bool
	}{
		{"AWS", "aws", false},
		{"MinIO", "minio", true},
		{"Backblaze", "backblaze", true},
		{"DigitalOcean", "digitalocean", false},
		{"Unknown", "unknown", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RequiresPathStyleAddressing(tt.provider)
			if got != tt.want {
				t.Errorf("RequiresPathStyleAddressing(%q) = %v, want %v", tt.provider, got, tt.want)
			}
		})
	}
}
