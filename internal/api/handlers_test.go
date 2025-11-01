package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	"github.com/kenneth/s3-encryption-gateway/internal/metrics"
	"github.com/kenneth/s3-encryption-gateway/internal/s3"
	"github.com/sirupsen/logrus"
)

// mockS3Client is a mock implementation of s3.Client for testing.
type mockS3Client struct {
	objects  map[string][]byte
	metadata map[string]map[string]string
	errors   map[string]error
}

func newMockS3Client() *mockS3Client {
	return &mockS3Client{
		objects:  make(map[string][]byte),
		metadata: make(map[string]map[string]string),
		errors:   make(map[string]error),
	}
}

func (m *mockS3Client) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string) error {
	if err := m.errors[bucket+"/"+key+"/put"]; err != nil {
		return err
	}
	data, _ := io.ReadAll(reader)
	m.objects[bucket+"/"+key] = data
	m.metadata[bucket+"/"+key] = metadata
	return nil
}

func (m *mockS3Client) GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, map[string]string, error) {
	if err := m.errors[bucket+"/"+key+"/get"]; err != nil {
		return nil, nil, err
	}
	data, ok := m.objects[bucket+"/"+key]
	if !ok {
		return nil, nil, &s3Error{code: "NoSuchKey", message: "Object not found"}
	}
	meta := m.metadata[bucket+"/"+key]
	if meta == nil {
		meta = make(map[string]string)
	}
	return io.NopCloser(bytes.NewReader(data)), meta, nil
}

func (m *mockS3Client) DeleteObject(ctx context.Context, bucket, key string) error {
	if err := m.errors[bucket+"/"+key+"/delete"]; err != nil {
		return err
	}
	delete(m.objects, bucket+"/"+key)
	delete(m.metadata, bucket+"/"+key)
	return nil
}

func (m *mockS3Client) HeadObject(ctx context.Context, bucket, key string) (map[string]string, error) {
	if err := m.errors[bucket+"/"+key+"/head"]; err != nil {
		return nil, err
	}
	meta, ok := m.metadata[bucket+"/"+key]
	if !ok {
		return nil, &s3Error{code: "NoSuchKey", message: "Object not found"}
	}
	if meta == nil {
		meta = make(map[string]string)
	}
	return meta, nil
}

func (m *mockS3Client) ListObjects(ctx context.Context, bucket, prefix string, opts s3.ListOptions) ([]s3.ObjectInfo, error) {
	if err := m.errors[bucket+"/list"]; err != nil {
		return nil, err
	}
	var objects []s3.ObjectInfo
	for key := range m.objects {
		if len(key) > len(bucket)+1 && key[:len(bucket)+1] == bucket+"/" {
			objKey := key[len(bucket)+1:]
			if prefix == "" || len(objKey) >= len(prefix) && objKey[:len(prefix)] == prefix {
				objects = append(objects, s3.ObjectInfo{Key: objKey})
			}
		}
	}
	return objects, nil
}

type s3Error struct {
	code    string
	message string
}

func (e *s3Error) Error() string {
	return e.message
}

var (
	sharedTestMetrics *metrics.Metrics
	metricsOnce       sync.Once
)

func getTestMetrics() *metrics.Metrics {
	metricsOnce.Do(func() {
		sharedTestMetrics = metrics.NewMetrics()
	})
	return sharedTestMetrics
}

func TestHandler_HandleHealth(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	handler := NewHandler(newMockS3Client(), logger, getTestMetrics())

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestHandler_HandlePutObject(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	handler := NewHandler(mockClient, logger, getTestMetrics())

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	tests := []struct {
		name     string
		bucket   string
		key      string
		body     string
		wantCode int
	}{
		{
			name:     "valid put",
			bucket:   "test-bucket",
			key:      "test-key",
			body:     "test data",
			wantCode: http.StatusOK,
		},
		{
			name:     "missing bucket",
			bucket:   "",
			key:      "test-key",
			body:     "test data",
			wantCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var url string
			if tt.bucket == "" {
				// For missing bucket, use a URL that doesn't match the route pattern
				url = "/missing-bucket-test"
			} else {
				url = "/" + tt.bucket + "/" + tt.key
			}
			req := httptest.NewRequest("PUT", url, bytes.NewReader([]byte(tt.body)))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d", tt.wantCode, w.Code)
			}

			if tt.wantCode == http.StatusOK {
				// Verify object was stored
				_, _, err := mockClient.GetObject(context.Background(), tt.bucket, tt.key)
				if err != nil {
					t.Errorf("object should have been stored: %v", err)
				}
			}
		})
	}
}

func TestHandler_HandleGetObject(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	handler := NewHandler(mockClient, logger, getTestMetrics())

	// Pre-populate with test data
	mockClient.PutObject(context.Background(), "test-bucket", "test-key", bytes.NewReader([]byte("test data")), nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("GET", "/test-bucket/test-key", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	if w.Body.String() != "test data" {
		t.Errorf("expected body 'test data', got %q", w.Body.String())
	}
}

func TestHandler_HandleDeleteObject(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	handler := NewHandler(mockClient, logger, getTestMetrics())

	// Pre-populate with test data
	mockClient.PutObject(context.Background(), "test-bucket", "test-key", bytes.NewReader([]byte("test data")), nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("DELETE", "/test-bucket/test-key", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, w.Code)
	}

	// Verify object was deleted
	_, _, err := mockClient.GetObject(context.Background(), "test-bucket", "test-key")
	if err == nil {
		t.Error("object should have been deleted")
	}
}

func TestHandler_HandleHeadObject(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	handler := NewHandler(mockClient, logger, getTestMetrics())

	metadata := map[string]string{"content-type": "text/plain"}
	mockClient.PutObject(context.Background(), "test-bucket", "test-key", bytes.NewReader([]byte("test")), metadata)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("HEAD", "/test-bucket/test-key", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestHandler_HandleListObjects(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	handler := NewHandler(mockClient, logger, getTestMetrics())

	// Pre-populate with test data
	mockClient.PutObject(context.Background(), "test-bucket", "key1", bytes.NewReader([]byte("data1")), nil)
	mockClient.PutObject(context.Background(), "test-bucket", "key2", bytes.NewReader([]byte("data2")), nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("GET", "/test-bucket", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	if w.Header().Get("Content-Type") != "application/xml" {
		t.Errorf("expected Content-Type application/xml, got %s", w.Header().Get("Content-Type"))
	}
}