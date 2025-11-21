package test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
)

// ToxicServer is a wrapper around httptest.Server that can inject faults.
type ToxicServer struct {
	server *httptest.Server
	mu     sync.Mutex
	// Fault configuration
	latency       time.Duration
	failCount     int           // Number of times to fail before succeeding
	failCode      int           // HTTP status code to return on failure
	failBody      string        // Body to return on failure
	requestCount  int           // Current request count
	totalRequests int32         // Total requests received
	hangForever   bool          // If true, hang connection until client times out
}

func NewToxicServer() *ToxicServer {
	ts := &ToxicServer{}
	ts.server = httptest.NewServer(http.HandlerFunc(ts.handleRequest))
	return ts
}

func (ts *ToxicServer) Close() {
	ts.server.Close()
}

func (ts *ToxicServer) URL() string {
	return ts.server.URL
}

func (ts *ToxicServer) Reset() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.latency = 0
	ts.failCount = 0
	ts.failCode = 0
	ts.failBody = ""
	ts.requestCount = 0
	ts.hangForever = false
	atomic.StoreInt32(&ts.totalRequests, 0)
}

func (ts *ToxicServer) SetBehavior(latency time.Duration, failCount int, failCode int) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.latency = latency
	ts.failCount = failCount
	ts.failCode = failCode
	ts.requestCount = 0
}

func (ts *ToxicServer) SetHang(hang bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.hangForever = hang
}

func (ts *ToxicServer) GetTotalRequests() int32 {
	return atomic.LoadInt32(&ts.totalRequests)
}

func (ts *ToxicServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&ts.totalRequests, 1)

	ts.mu.Lock()
	latency := ts.latency
	shouldFail := ts.requestCount < ts.failCount
	failCode := ts.failCode
	hang := ts.hangForever
	if shouldFail {
		ts.requestCount++
	}
	ts.mu.Unlock()

	if hang {
		// Sleep longer than any reasonable timeout
		time.Sleep(30 * time.Second)
		return
	}

	if latency > 0 {
		time.Sleep(latency)
	}

	if shouldFail && failCode > 0 {
		w.WriteHeader(failCode)
		// AWS SDK expects XML error response for some codes, but simple errors might suffice for chaos testing
		// simulating S3 error response structure
		w.Header().Set("Content-Type", "application/xml")
		errorXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>InternalError</Code>
    <Message>We encountered an internal error. Please try again.</Message>
    <RequestId>4442587FB7D0A2F9</RequestId>
    <HostId>...</HostId>
</Error>`)
		if failCode == http.StatusServiceUnavailable || failCode == 429 {
			errorXML = fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>SlowDown</Code>
    <Message>Reduce your request rate.</Message>
    <RequestId>4442587FB7D0A2F9</RequestId>
</Error>`)
		}
		w.Write([]byte(errorXML))
		return
	}

	// Success path - act like a minimal S3 server
	w.Header().Set("x-amz-request-id", "test-request-id")
	w.Header().Set("x-amz-id-2", "test-host-id")

	switch r.Method {
	case "PUT":
		w.Header().Set("ETag", "\"test-etag\"")
		w.WriteHeader(http.StatusOK)
	case "GET":
		w.Header().Set("ETag", "\"test-etag\"")
		w.Header().Set("Content-Type", "application/octet-stream")
		// Echo back headers with x-amz-meta- prefix for metadata tests if needed
		for k, v := range r.Header {
			if len(k) > 11 && k[:11] == "x-amz-meta-" {
				w.Header().Set(k, v[0])
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test content"))
	case "HEAD":
		w.Header().Set("ETag", "\"test-etag\"")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", "12")
		w.WriteHeader(http.StatusOK)
	case "DELETE":
		w.WriteHeader(http.StatusNoContent)
	}
}

func TestChaos_BackendThrottling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping chaos test in short mode")
	}

	// 1. Start Toxic Server
	backend := NewToxicServer()
	defer backend.Close()

	// 2. Configure Gateway to use Toxic Server
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0", // Random port
		Encryption: config.EncryptionConfig{
			KeyFile:  "", // Using Password instead of KeyFile based on struct definition
			Password: "test-password",
		},
		Backend: config.BackendConfig{
			Endpoint:     backend.URL(),
			AccessKey:    "test-access",
			SecretKey:    "test-secret",
			Region:       "us-east-1",
			UsePathStyle: true,
		},
		// Assuming Logging config structure matches what we saw in config.go
		// Actually config.go doesn't seem to have a Level field in LoggingConfig,
		// it has AccessLogFormat and RedactHeaders.
		// The LogLevel is at the root of Config struct.
		LogLevel: "error",
	}

	gateway := StartGateway(t, cfg)
	defer gateway.Close()
	client := gateway.GetHTTPClient()

	// Case 1: Transient 429 (Throttling) - Should succeed due to SDK retries
	// AWS SDK v2 default retryer retries on 429/503.
	// Set backend to fail 2 times with 429, then succeed.
	backend.Reset()
	backend.SetBehavior(0, 2, 429)

	t.Run("Transient Throttling", func(t *testing.T) {
		req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/test-bucket/key1", gateway.URL), bytes.NewReader([]byte("data")))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("Expected success after retries, got status %d: %s", resp.StatusCode, body)
		}

		// Verify backend received retries (1 initial + 2 retries = 3 requests total)
		// Or 1 initial + 1 retry (if failCount=1 means 1 failure then success)
		// failCount=2 means 1st request fails, 2nd request fails, 3rd succeeds.
		total := backend.GetTotalRequests()
		if total < 3 {
			t.Errorf("Expected at least 3 requests to backend (retries), got %d", total)
		}
	})

	// Case 2: Persistent 429 - Should eventually fail
	backend.Reset()
	backend.SetBehavior(0, 10, 429) // Fail more times than default max retries (usually 3)

	t.Run("Persistent Throttling", func(t *testing.T) {
		req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/test-bucket/key2", gateway.URL), bytes.NewReader([]byte("data")))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusInternalServerError && resp.StatusCode != http.StatusServiceUnavailable {
			// Note: Gateway might return 500 if backend errors out, or propagate 503.
			// Current implementation likely wraps error in 500 unless mapped.
			// Let's check what it actually returns.
			t.Logf("Got status code: %d", resp.StatusCode)
		}

		// Should definitely fail
		if resp.StatusCode == http.StatusOK {
			t.Error("Expected failure for persistent throttling, got 200 OK")
		}
	})
}

func TestChaos_Backend500(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping chaos test in short mode")
	}

	// 1. Start Toxic Server
	backend := NewToxicServer()
	defer backend.Close()

	// 2. Configure Gateway
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Encryption: config.EncryptionConfig{
			Password: "test-password",
		},
		Backend: config.BackendConfig{
			Endpoint:     backend.URL(),
			AccessKey:    "test-access",
			SecretKey:    "test-secret",
			Region:       "us-east-1",
			UsePathStyle: true,
		},
		LogLevel: "error",
	}

	gateway := StartGateway(t, cfg)
	defer gateway.Close()
	client := gateway.GetHTTPClient()

	// Case 1: Transient 500 - Should succeed due to retries
	backend.Reset()
	backend.SetBehavior(0, 2, 500)

	t.Run("Transient 500", func(t *testing.T) {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/test-bucket/key1", gateway.URL), nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected success after retries, got status %d", resp.StatusCode)
		}

		total := backend.GetTotalRequests()
		if total < 3 {
			t.Errorf("Expected retries, got %d requests", total)
		}
	})

	// Case 2: Persistent 500 - Should fail
	backend.Reset()
	backend.SetBehavior(0, 10, 500)

	t.Run("Persistent 500", func(t *testing.T) {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/test-bucket/key2", gateway.URL), nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("Expected failure for persistent 500s, got 200 OK")
		}
	})
}

func TestChaos_NetworkTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping chaos test in short mode")
	}

	// 1. Start Toxic Server
	backend := NewToxicServer()
	defer backend.Close()

	// 2. Configure Gateway
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Encryption: config.EncryptionConfig{
			Password: "test-password",
		},
		Backend: config.BackendConfig{
			Endpoint:     backend.URL(),
			AccessKey:    "test-access",
			SecretKey:    "test-secret",
			Region:       "us-east-1",
			UsePathStyle: true,
		},
		LogLevel: "error",
	}

	// Start gateway with the config
	gateway := StartGateway(t, cfg)
	defer gateway.Close()
	client := gateway.GetHTTPClient()

	// Set client timeout for the test request to avoid hanging forever if gateway hangs
	client.Timeout = 5 * time.Second

	backend.Reset()
	backend.SetHang(true)

	t.Run("Backend Hangs", func(t *testing.T) {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/test-bucket/key-hang", gateway.URL), nil)
		
		// We expect this to eventually fail, but it might take time depending on AWS SDK default timeouts.
		// AWS SDK v2 defaults: ConnectTimeout 30s, ReadTimeout usually longer.
		// If we can't configure it easily in test, we might just verify it returns an error eventually.
		// But since we don't want the test to run for minutes, we rely on the client.Timeout of 5s above.
		// If the gateway hangs, the client.Do will return timeout.
		// If the gateway correctly handles context cancellation or has its own timeout, it might return earlier.
		
		// Actually, the client.Do timeout will trigger client-side context cancellation.
		// We want to check if the gateway returns 504 Gateway Timeout if we wait long enough,
		// OR if it simply respects the client closing the connection.
		
		// Let's see if we can force a shorter timeout via context for the request.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req = req.WithContext(ctx)

		start := time.Now()
		resp, err := client.Do(req)
		duration := time.Since(start)
		
		if err != nil {
			// Expected timeout
			t.Logf("Request failed as expected after %v: %v", duration, err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("Expected failure when backend hangs, got 200 OK")
		} else {
			t.Logf("Got status code %d after %v", resp.StatusCode, duration)
		}
	})
}
