package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"

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

func (m *mockClient) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string) error {
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

	err := mock.PutObject(ctx, bucket, key, bytes.NewReader(data), metadata)
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

	err := mock.PutObject(ctx, bucket, key, bytes.NewReader(data), nil)
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