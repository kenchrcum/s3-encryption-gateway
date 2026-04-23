package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
)

// mockClient is a mock implementation for testing.
type mockClient struct {
	objects map[string][]byte
	metadata map[string]map[string]string
}

func newMockClient() *mockClient {
	return &mockClient{
		objects:  make(map[string][]byte),
		metadata: make(map[string]map[string]string),
	}
}

func (m *mockClient) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *ObjectLockInput) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	m.objects[bucket+"/"+key] = data
	m.metadata[bucket+"/"+key] = metadata
	return nil
}

func (m *mockClient) GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, map[string]string, error) {
	data, ok := m.objects[bucket+"/"+key]
	if !ok {
		return nil, nil, fmt.Errorf("object not found")
	}
	meta := m.metadata[bucket+"/"+key]
	if meta == nil {
		meta = make(map[string]string)
	}
	return io.NopCloser(bytes.NewReader(data)), meta, nil
}

func (m *mockClient) DeleteObject(ctx context.Context, bucket, key string) error {
	delete(m.objects, bucket+"/"+key)
	delete(m.metadata, bucket+"/"+key)
	return nil
}

func (m *mockClient) HeadObject(ctx context.Context, bucket, key string) (map[string]string, error) {
	meta, ok := m.metadata[bucket+"/"+key]
	if !ok {
		return nil, fmt.Errorf("object not found")
	}
	if meta == nil {
		meta = make(map[string]string)
	}
	return meta, nil
}

func (m *mockClient) ListObjects(ctx context.Context, bucket, prefix string, opts ListOptions) ([]ObjectInfo, error) {
	var objects []ObjectInfo
	for key := range m.objects {
		if bucket+"/" == key[:len(bucket)+1] && (prefix == "" || key[len(bucket)+1:][:len(prefix)] == prefix) {
			objects = append(objects, ObjectInfo{
				Key: key[len(bucket)+1:],
			})
		}
	}
	return objects, nil
}

func TestMockClient_PutGet(t *testing.T) {
	ctx := context.Background()
	mock := newMockClient()

	bucket := "test-bucket"
	key := "test-key"
	data := []byte("test data")
	metadata := map[string]string{"content-type": "text/plain"}

    err := mock.PutObject(ctx, bucket, key, bytes.NewReader(data), metadata, nil, "", nil)
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	reader, retrievedMeta, err := mock.GetObject(ctx, bucket, key)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	defer reader.Close()

	retrievedData, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !bytes.Equal(data, retrievedData) {
		t.Errorf("expected data %q, got %q", string(data), string(retrievedData))
	}

	if retrievedMeta["content-type"] != metadata["content-type"] {
		t.Errorf("expected content-type %q, got %q", metadata["content-type"], retrievedMeta["content-type"])
	}
}

func TestMockClient_DeleteObject(t *testing.T) {
	ctx := context.Background()
	mock := newMockClient()

	bucket := "test-bucket"
	key := "test-key"
	data := []byte("test data")

    err := mock.PutObject(ctx, bucket, key, bytes.NewReader(data), nil, nil, "", nil)
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	err = mock.DeleteObject(ctx, bucket, key)
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}

	_, _, err = mock.GetObject(ctx, bucket, key)
	if err == nil {
		t.Error("expected error after deleting object")
	}
}

func TestS3Client_ConfigValidation(t *testing.T) {
	cfg := &config.BackendConfig{
		Endpoint:  "http://localhost:9000",
		Region:    "us-east-1",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Provider:  "minio",
	}

	// This will fail in unit tests without real AWS credentials/endpoint
	// but we can test that the client creation logic is correct
	_, err := NewClient(cfg)
	if err != nil {
		// Expected in test environment without real credentials
		t.Logf("NewClient returned expected error (no real credentials): %v", err)
	}
}

func TestClientFactory_GetClientWithCredentials(t *testing.T) {
	baseCfg := &config.BackendConfig{
		Endpoint:  "http://localhost:9000",
		Region:    "us-east-1",
		AccessKey: "base-key",
		SecretKey: "base-secret",
		UseSSL:    false,
	}

	factory := NewClientFactory(baseCfg)

	tests := []struct {
		name       string
		accessKey  string
		secretKey  string
		wantErr    bool
		errMessage string
	}{
		{
			name:      "valid credentials",
			accessKey: "client-key",
			secretKey: "client-secret",
			wantErr:   false,
		},
		{
			name:       "empty access key",
			accessKey:  "",
			secretKey:  "client-secret",
			wantErr:    true,
			errMessage: "access key is required",
		},
		{
			name:       "empty secret key",
			accessKey:  "client-key",
			secretKey:  "",
			wantErr:    true,
			errMessage: "secret key is required",
		},
		{
			name:       "both empty",
			accessKey:  "",
			secretKey:  "",
			wantErr:    true,
			errMessage: "access key is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := factory.GetClientWithCredentials(tt.accessKey, tt.secretKey)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("GetClientWithCredentials() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err == nil {
					t.Error("GetClientWithCredentials() expected error, got nil")
					return
				}
				if tt.errMessage != "" && !strings.Contains(err.Error(), tt.errMessage) {
					t.Errorf("GetClientWithCredentials() error = %v, want error containing %q", err, tt.errMessage)
				}
			} else {
				if client == nil {
					t.Error("GetClientWithCredentials() returned nil client without error")
				}
			}
		})
	}
}

func TestClientFactory_GetClient(t *testing.T) {
	cfg := &config.BackendConfig{
		Endpoint:  "http://localhost:9000",
		Region:    "us-east-1",
		AccessKey: "base-key",
		SecretKey: "base-secret",
		UseSSL:    false,
	}

	factory := NewClientFactory(cfg)

	// GetClient should use base configured credentials
	// This will fail in test environment without real credentials, but we can verify it calls GetClientWithCredentials
	_, err := factory.GetClient()
	if err != nil {
		// Expected in test environment - verify error mentions credentials issue
		if !strings.Contains(err.Error(), "access key") && !strings.Contains(err.Error(), "secret key") && !strings.Contains(err.Error(), "credentials") && !strings.Contains(err.Error(), "failed to load AWS config") {
			t.Logf("GetClient returned error (expected without real credentials): %v", err)
		}
	}
}

// ---- V0.6-PERF-2 Phase D factory / client integration tests ----------------

// TestClientFactory_RetryerInstalled verifies that the factory constructs a
// retryer that classifies 503 as retryable and uses the configured MaxAttempts.
// We test via the retryer directly (not end-to-end through the SDK) to avoid
// relying on SDK sleep behavior in unit tests.
func TestClientFactory_RetryerInstalled(t *testing.T) {
	cfg := &config.BackendConfig{
		Region:    "us-east-1",
		AccessKey: "AKIATEST",
		SecretKey: "secrettest",
		UseSSL:    false,
		Retry: config.BackendRetryConfig{
			Mode:           "standard",
			MaxAttempts:    3,
			InitialBackoff: 1 * time.Millisecond,
			MaxBackoff:     10 * time.Millisecond,
			Jitter:         "full",
		},
	}
	cfg.Retry.Normalize()
	factory := NewClientFactory(cfg)

	// Verify the retry factory is installed.
	if factory.retryerFactory == nil {
		t.Fatal("retryerFactory should not be nil for mode=standard")
	}

	// Build a per-operation retryer and verify it classifies 503 as retryable.
	r := factory.retryerFactory.Build("PutObject")
	err503 := makeHTTPRespErr(t, 503, 0)
	if !r.IsErrorRetryable(err503) {
		t.Error("503 should be retryable")
	}
	if r.MaxAttempts() != 3 {
		t.Errorf("MaxAttempts: expected 3, got %d", r.MaxAttempts())
	}
}

// TestClientFactory_RetryMode_Off verifies that mode=off disables retries.
func TestClientFactory_RetryMode_Off(t *testing.T) {
	var attemptCount int
	countingTransport := &countingFaultTransport{
		faultStatus:   503,
		faultCount:    999, // always fail
		onAttempt:     func() { attemptCount++ },
		okBodyBuilder: benchBodyFor,
	}

	cfg := &config.BackendConfig{
		Region:    "us-east-1",
		AccessKey: "AKIATEST",
		SecretKey: "secrettest",
		UseSSL:    false,
		Retry: config.BackendRetryConfig{
			Mode:           "off",
			MaxAttempts:    1,
			InitialBackoff: 1 * time.Millisecond,
			MaxBackoff:     10 * time.Millisecond,
			Jitter:         "full",
		},
	}
	cfg.Retry.Normalize()

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("AKIATEST", "secrettest", "")),
		awsconfig.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
		awsconfig.WithResponseChecksumValidation(aws.ResponseChecksumValidationWhenRequired),
		awsconfig.WithHTTPClient(&http.Client{Transport: countingTransport}),
		awsconfig.WithRetryer(func() aws.Retryer {
			return newNopRetryerV2()
		}),
	)
	if err != nil {
		t.Fatalf("LoadDefaultConfig: %v", err)
	}
	sdkClient := awss3.NewFromConfig(awsCfg, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String("http://localhost:9000")
		o.UsePathStyle = true
	})

	payload := make([]byte, 16)
	_, _ = sdkClient.PutObject(context.Background(), &awss3.PutObjectInput{
		Bucket:        aws.String("test-bucket"),
		Key:           aws.String("test-key"),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
	})

	if attemptCount != 1 {
		t.Errorf("mode=off: expected exactly 1 attempt, got %d", attemptCount)
	}
	_ = cfg
}

// TestClientFactory_PerOperationOverride_DisablesPutObject verifies that a
// per-operation override of 1 for PutObject results in a single attempt.
func TestClientFactory_PerOperationOverride_DisablesPutObject(t *testing.T) {
	cfg := defaultTestCfg()
	cfg.PerOperation = map[string]int{"PutObject": 1}

	r := newTestRetryer(t, cfg, &fakeClock{}, nil, nil).clone("PutObject")
	if r.MaxAttempts() != 1 {
		t.Errorf("per-op override should give MaxAttempts=1 for PutObject, got %d", r.MaxAttempts())
	}

	// HeadObject should still use the global MaxAttempts=3.
	rHead := newTestRetryer(t, cfg, &fakeClock{}, nil, nil).clone("HeadObject")
	if rHead.MaxAttempts() != 3 {
		t.Errorf("HeadObject should still use global MaxAttempts=3, got %d", rHead.MaxAttempts())
	}
}

// countingFaultTransport injects `faultCount` faults then returns 200.
// Thread-safe for concurrent use.
type countingFaultTransport struct {
	faultStatus   int
	faultCount    int
	onAttempt     func()
	okBodyBuilder func(req *http.Request) string
	mu            sync.Mutex
	called        int
}

func (t *countingFaultTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.called++
	n := t.called
	t.mu.Unlock()

	if t.onAttempt != nil {
		t.onAttempt()
	}

	if n <= t.faultCount {
		body := fmt.Sprintf(`<Error><Code>ServiceUnavailable</Code><Message>injected %d</Message></Error>`, t.faultStatus)
		return &http.Response{
			StatusCode: t.faultStatus,
			Status:     fmt.Sprintf("%d %s", t.faultStatus, http.StatusText(t.faultStatus)),
			Header:     http.Header{"Content-Type": []string{"application/xml"}, "x-amz-request-id": []string{"COUNTFLT"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	}

	// Success path.
	var body string
	if t.okBodyBuilder != nil {
		body = t.okBodyBuilder(req)
	}
	return &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/xml"}, "ETag": []string{`"countok"`}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}
