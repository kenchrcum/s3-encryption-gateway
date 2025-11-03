package s3

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
)

// ProxyClient forwards HTTP requests to the backend with original headers intact.
// This is used when useClientCredentials is enabled and we receive Signature V4 requests,
// where the secret key is not available but the request is already signed.
type ProxyClient struct {
	backendURL *url.URL
	httpClient *http.Client
	config     *config.BackendConfig
}

// NewProxyClient creates a new proxy client that forwards requests to the backend.
func NewProxyClient(cfg *config.BackendConfig) (*ProxyClient, error) {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		return nil, fmt.Errorf("backend endpoint is required")
	}

	backendURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid backend endpoint: %w", err)
	}

	// Normalize endpoint
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "https://" + endpoint
		backendURL, err = url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to parse normalized endpoint: %w", err)
		}
	}

	return &ProxyClient{
		backendURL: backendURL,
		httpClient: &http.Client{},
		config:     cfg,
	}, nil
}

// ForwardRequest forwards an HTTP request to the backend, preserving original headers.
func (p *ProxyClient) ForwardRequest(ctx context.Context, originalReq *http.Request, method, bucket, key string, body io.Reader) (*http.Response, error) {
	// Build backend URL
	backendPath := fmt.Sprintf("/%s", bucket)
	if key != "" {
		backendPath = fmt.Sprintf("/%s/%s", bucket, key)
	}

	backendURL := &url.URL{
		Scheme:   p.backendURL.Scheme,
		Host:     p.backendURL.Host,
		Path:     backendPath,
		RawQuery: originalReq.URL.RawQuery, // Preserve query parameters
	}

	// Create request to backend
	req, err := http.NewRequestWithContext(ctx, method, backendURL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create backend request: %w", err)
	}

	// Copy headers from original request (including Authorization)
	for k, v := range originalReq.Header {
		// Skip Host header - we'll set it to backend
		if strings.EqualFold(k, "Host") {
			continue
		}
		// Copy all other headers including Authorization
		req.Header[k] = v
	}

	// Set Host header to backend
	req.Host = backendURL.Host

	// Make request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to forward request to backend: %w", err)
	}

	return resp, nil
}

// PutObject forwards a PUT request to the backend.
func (p *ProxyClient) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64) error {
	return fmt.Errorf("ProxyClient.PutObject not implemented - use ForwardRequest in handler")
}

// GetObject forwards a GET request to the backend.
func (p *ProxyClient) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	return nil, nil, fmt.Errorf("ProxyClient.GetObject not implemented - use ForwardRequest in handler")
}

// DeleteObject forwards a DELETE request to the backend.
func (p *ProxyClient) DeleteObject(ctx context.Context, bucket, key string, versionID *string) error {
	return fmt.Errorf("ProxyClient.DeleteObject not implemented - use ForwardRequest in handler")
}

// HeadObject forwards a HEAD request to the backend.
func (p *ProxyClient) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	return nil, fmt.Errorf("ProxyClient.HeadObject not implemented - use ForwardRequest in handler")
}

// ListObjects forwards a LIST request to the backend.
func (p *ProxyClient) ListObjects(ctx context.Context, bucket, prefix string, opts ListOptions) ([]ObjectInfo, error) {
	return nil, fmt.Errorf("ProxyClient.ListObjects not implemented - use ForwardRequest in handler")
}

// CreateMultipartUpload is not implemented
func (p *ProxyClient) CreateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error) {
	return "", fmt.Errorf("ProxyClient.CreateMultipartUpload not implemented")
}

// UploadPart is not implemented
func (p *ProxyClient) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, reader io.Reader) (string, error) {
	return "", fmt.Errorf("ProxyClient.UploadPart not implemented")
}

// CompleteMultipartUpload is not implemented
func (p *ProxyClient) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart) (string, error) {
	return "", fmt.Errorf("ProxyClient.CompleteMultipartUpload not implemented")
}

// AbortMultipartUpload is not implemented
func (p *ProxyClient) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	return fmt.Errorf("ProxyClient.AbortMultipartUpload not implemented")
}

// ListParts is not implemented
func (p *ProxyClient) ListParts(ctx context.Context, bucket, key, uploadID string) ([]PartInfo, error) {
	return nil, fmt.Errorf("ProxyClient.ListParts not implemented")
}

// CopyObject is not implemented
func (p *ProxyClient) CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string) (string, map[string]string, error) {
	return "", nil, fmt.Errorf("ProxyClient.CopyObject not implemented")
}

// DeleteObjects is not implemented
func (p *ProxyClient) DeleteObjects(ctx context.Context, bucket string, keys []ObjectIdentifier) ([]DeletedObject, []ErrorObject, error) {
	return nil, nil, fmt.Errorf("ProxyClient.DeleteObjects not implemented")
}

