package harness

import (
	"io"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
)

// echoTransport is a trivial RoundTripper that always returns 200 OK.
type echoTransport struct{}

func (echoTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(http.NoBody),
		Request:    req,
	}, nil
}

func newTestRequest(t *testing.T) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "http://minio.local/bucket/key", http.NoBody)
	return req
}

// TestFaultyS3_InjectsStatus verifies that the FaultHTTPStatus class produces
// the configured status code instead of forwarding to the inner transport.
func TestFaultyS3_InjectsStatus(t *testing.T) {
	rules := []FaultRule{
		{
			Class:          FaultHTTPStatus,
			StatusCode:     503,
			ProbabilityPct: 100, // always inject
		},
	}
	f := NewFaultyRoundTripper(echoTransport{}, 0, rules)
	resp, err := f.RoundTrip(newTestRequest(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 503 {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

// TestFaultyS3_InjectsNetworkError verifies that FaultNetworkError returns the
// configured error without hitting the inner transport.
func TestFaultyS3_InjectsNetworkError(t *testing.T) {
	rules := []FaultRule{
		{
			Class:          FaultNetworkError,
			NetworkErr:     syscall.ECONNRESET,
			ProbabilityPct: 100,
		},
	}
	f := NewFaultyRoundTripper(echoTransport{}, 0, rules)
	_, err := f.RoundTrip(newTestRequest(t))
	if err == nil {
		t.Fatal("expected ECONNRESET, got nil")
	}
	if err != syscall.ECONNRESET {
		t.Fatalf("expected ECONNRESET, got %v", err)
	}
}

// TestFaultyS3_Deterministic verifies that given the same seed and rules,
// two FaultyRoundTrippers produce the same injection sequence.
func TestFaultyS3_Deterministic(t *testing.T) {
	rules := []FaultRule{
		{
			Class:          FaultHTTPStatus,
			StatusCode:     503,
			ProbabilityPct: 50,
		},
	}
	const n = 100
	const seed = int64(42)

	results1 := make([]int, n)
	f1 := NewFaultyRoundTripper(echoTransport{}, seed, rules)
	for i := range results1 {
		resp, err := f1.RoundTrip(newTestRequest(t))
		if err != nil {
			t.Fatalf("run1[%d] unexpected err: %v", i, err)
		}
		results1[i] = resp.StatusCode
	}

	results2 := make([]int, n)
	f2 := NewFaultyRoundTripper(echoTransport{}, seed, rules)
	for i := range results2 {
		resp, err := f2.RoundTrip(newTestRequest(t))
		if err != nil {
			t.Fatalf("run2[%d] unexpected err: %v", i, err)
		}
		results2[i] = resp.StatusCode
	}

	for i := range results1 {
		if results1[i] != results2[i] {
			t.Fatalf("results diverged at index %d: %d vs %d", i, results1[i], results2[i])
		}
	}
}

// TestFaultyS3_ZeroProbability verifies that ProbabilityPct=0 never injects.
func TestFaultyS3_ZeroProbability(t *testing.T) {
	rules := []FaultRule{
		{
			Class:          FaultHTTPStatus,
			StatusCode:     503,
			ProbabilityPct: 0, // never
		},
	}
	f := NewFaultyRoundTripper(echoTransport{}, 0, rules)
	for i := 0; i < 20; i++ {
		resp, err := f.RoundTrip(newTestRequest(t))
		if err != nil {
			t.Fatalf("[%d] unexpected error: %v", i, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("[%d] expected 200 (passthrough), got %d", i, resp.StatusCode)
		}
	}
}

// TestFaultyS3_OperationFilter verifies that rules are only applied to matching paths.
func TestFaultyS3_OperationFilter(t *testing.T) {
	rules := []FaultRule{
		{
			Class:           FaultHTTPStatus,
			StatusCode:      503,
			ProbabilityPct:  100,
			OperationFilter: []string{"uploadpart"},
		},
	}
	f := NewFaultyRoundTripper(echoTransport{}, 0, rules)

	// This URL does not match "uploadpart" → should pass through.
	req := httptest.NewRequest(http.MethodPut, "http://minio.local/bucket/key", http.NoBody)
	resp, err := f.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("filter should not have matched, expected 200, got %d", resp.StatusCode)
	}

	// URL containing "uploadpart" should be faulted.
	req2 := httptest.NewRequest(http.MethodPut, "http://minio.local/bucket/key?uploadId=abc&partNumber=1", http.NoBody)
	// The filter is case-insensitive; "uploadId" in the query won't match "uploadpart".
	// Use a path that does match.
	req3 := httptest.NewRequest(http.MethodPut, "http://minio.local/bucket/key?uploadpart=true", http.NoBody)
	_ = req2
	resp3, err3 := f.RoundTrip(req3)
	if err3 != nil {
		t.Fatalf("unexpected error: %v", err3)
	}
	if resp3.StatusCode != 503 {
		t.Fatalf("filter should have matched, expected 503, got %d", resp3.StatusCode)
	}
}

// TestFaultyS3_RetryAfterHeader verifies that RetryAfterSeconds injects the header.
func TestFaultyS3_RetryAfterHeader(t *testing.T) {
	rules := []FaultRule{
		{
			Class:             FaultHTTPStatus,
			StatusCode:        503,
			RetryAfterSeconds: 5,
			ProbabilityPct:    100,
		},
	}
	f := NewFaultyRoundTripper(echoTransport{}, 0, rules)
	resp, err := f.RoundTrip(newTestRequest(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := resp.Header.Get("Retry-After"); got != "5" {
		t.Fatalf("expected Retry-After: 5, got %q", got)
	}
}

// TestFaultyS3_ConcurrentSafe verifies no data races under concurrent use.
// Run with -race to surface issues.
func TestFaultyS3_ConcurrentSafe(t *testing.T) {
	rules := []FaultRule{
		{
			Class:          FaultHTTPStatus,
			StatusCode:     503,
			ProbabilityPct: 30,
		},
	}
	f := NewFaultyRoundTripper(echoTransport{}, 1234, rules)

	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			resp, err := f.RoundTrip(newTestRequest(t))
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	for i := 0; i < 50; i++ {
		<-done
	}
}
