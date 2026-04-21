//go:build conformance

package conformance

// Load tests — tier-2, provider-agnostic.
//
// These tests replace the legacy shell-script + `cmd/loadtest` binary approach.
// They run fully in-process using the harness gateway and Testcontainers, so
// no pre-running gateway or backend is required.
//
// Design decisions:
//   - Object size and duration are intentionally small for the conformance gate
//     (100 KB objects, 5 s runs) so PR feedback is fast.
//   - The tests assert zero failures and non-zero throughput; they do NOT do
//     regression-baseline comparison (that lives in the soak target).
//   - The multipart test uses the real S3 multipart protocol (CreateMPU →
//     UploadPart → CompleteMPU), not the fake X-Part-Number header.
//   - Range scenarios mirror the legacy RangeTestScenario list.
//   - Workers and QPS are conservative to avoid saturating CI runners.

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kenneth/s3-encryption-gateway/test/harness"
	"github.com/kenneth/s3-encryption-gateway/test/provider"
)

// loadTestParams holds the tunable knobs for the in-conformance load runner.
// These are sized for CI: small objects, short duration, few workers.
type loadTestParams struct {
	workers    int
	duration   time.Duration
	qps        int           // requests per second per worker
	objectSize int64         // bytes
	chunkSize  int64         // encryption chunk size (bytes)
	partSize   int64         // multipart part size (bytes; must be ≥ 5 MiB per S3 spec)
}

// defaultLoadParams returns sensible defaults for the conformance gate.
func defaultLoadParams() loadTestParams {
	return loadTestParams{
		workers:    3,
		duration:   5 * time.Second,
		qps:        10,
		objectSize: 100 * 1024,       // 100 KiB — fast to encrypt and transfer
		chunkSize:  64 * 1024,        // 64 KiB — default chunk
		partSize:   5 * 1024 * 1024,  // 5 MiB — S3 minimum part size
	}
}

// loadResults is a minimal counter struct shared across workers.
type loadResults struct {
	total   int64
	success int64
	failed  int64
}

// testRangeLoad verifies that multiple concurrent workers can perform range
// GET requests against encrypted objects without errors. The test covers
// several range scenarios (first bytes, last bytes, cross-chunk, suffix,
// and a deliberately invalid range) and asserts:
//   - All valid-range requests succeed (HTTP 206).
//   - All invalid-range requests get HTTP 416.
//   - Zero worker-level errors (network failures, panics).
//   - Non-zero throughput.
func testRangeLoad(t *testing.T, inst provider.Instance) {
	t.Helper()
	p := defaultLoadParams()
	gw := harness.StartGateway(t, inst)

	// Upload the single shared object that all range workers read.
	objectKey := uniqueKey(t)
	objectData := bytes.Repeat([]byte("R"), int(p.objectSize))
	put(t, gw, inst.Bucket, objectKey, objectData)

	type rangeCase struct {
		name         string
		header       string
		expectedCode int
	}
	cases := []rangeCase{
		{"first_1KB", "bytes=0-1023", http.StatusPartialContent},
		{"last_1KB", fmt.Sprintf("bytes=%d-%d", p.objectSize-1024, p.objectSize-1), http.StatusPartialContent},
		{"suffix_512B", "bytes=-512", http.StatusPartialContent},
		{"cross_chunk", fmt.Sprintf("bytes=%d-%d", p.chunkSize/2, p.chunkSize/2+1023), http.StatusPartialContent},
		{"large_range", fmt.Sprintf("bytes=%d-%d", p.objectSize/4, p.objectSize/2), http.StatusPartialContent},
		{"invalid_range", "bytes=999999999-1000000000", http.StatusRequestedRangeNotSatisfiable},
	}

	var res loadResults
	interval := time.Second / time.Duration(p.qps)

	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	for w := 0; w < p.workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			client := gw.HTTPClient()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			idx := 0
			for {
				select {
				case <-stopCh:
					return
				case <-ticker.C:
					rc := cases[idx%len(cases)]
					idx++

					req, err := http.NewRequest("GET", objectURL(gw, inst.Bucket, objectKey), nil)
					if err != nil {
						atomic.AddInt64(&res.failed, 1)
						continue
					}
					req.Header.Set("Range", rc.header)

					resp, err := client.Do(req)
					atomic.AddInt64(&res.total, 1)
					if err != nil {
						atomic.AddInt64(&res.failed, 1)
						continue
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()

					if resp.StatusCode != rc.expectedCode {
						atomic.AddInt64(&res.failed, 1)
					} else {
						atomic.AddInt64(&res.success, 1)
					}
				}
			}
		}(w)
	}

	time.Sleep(p.duration)
	close(stopCh)
	wg.Wait()

	t.Logf("RangeLoad: total=%d success=%d failed=%d throughput=%.1f req/s",
		res.total, res.success, res.failed,
		float64(res.total)/p.duration.Seconds())

	if res.total == 0 {
		t.Error("no requests were issued during the load test")
	}
	if res.failed > 0 {
		t.Errorf("load test had %d failures out of %d requests", res.failed, res.total)
	}
}

// testMultipartLoad verifies that multiple concurrent workers can complete
// full multipart uploads (CreateMPU → UploadPart × N → CompleteMPU) without
// errors. Uses the real S3 multipart protocol via the harness gateway.
//
// Assertions:
//   - All uploads complete with HTTP 200.
//   - Zero worker-level errors.
//   - Non-zero throughput.
func testMultipartLoad(t *testing.T, inst provider.Instance) {
	t.Helper()
	p := defaultLoadParams()
	gw := harness.StartGateway(t, inst)

	// S3 multipart: minimum part size is 5 MiB for all parts except the last.
	// We upload 2 parts: one at 5 MiB (minimum) + one small tail part.
	part1Data := bytes.Repeat([]byte("P"), int(p.partSize))
	part2Data := []byte("tail")

	var res loadResults
	interval := time.Second / time.Duration(p.qps)

	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	for w := 0; w < p.workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			idx := int64(0)
			for {
				select {
				case <-stopCh:
					return
				case <-ticker.C:
					key := fmt.Sprintf("mpu-load/worker-%d/%d-%d", workerID, time.Now().UnixNano(), idx)
					idx++

					atomic.AddInt64(&res.total, 1)
					if err := runFullMPU(t, gw, inst.Bucket, key, part1Data, part2Data); err != nil {
						t.Logf("MPU worker %d failed: %v", workerID, err)
						atomic.AddInt64(&res.failed, 1)
					} else {
						atomic.AddInt64(&res.success, 1)
					}
				}
			}
		}(w)
	}

	time.Sleep(p.duration)
	close(stopCh)
	wg.Wait()

	t.Logf("MultipartLoad: total=%d success=%d failed=%d throughput=%.2f upload/s",
		res.total, res.success, res.failed,
		float64(res.total)/p.duration.Seconds())

	if res.total == 0 {
		t.Error("no uploads were attempted during the load test")
	}
	if res.failed > 0 {
		t.Errorf("multipart load test had %d failures out of %d uploads", res.failed, res.total)
	}
}

// runFullMPU executes a complete S3 multipart upload for the given key.
// It is deliberately not using the harness helpers so the concurrency model
// is explicit and per-call HTTP clients do not share state.
func runFullMPU(t *testing.T, gw *harness.Gateway, bucket, key string, parts ...[]byte) error {
	t.Helper()
	ctx := context.Background()
	_ = ctx

	client := gw.HTTPClient()

	// 1. CreateMultipartUpload
	initURL := fmt.Sprintf("%s/%s/%s?uploads", gw.URL, bucket, key)
	initResp, err := client.Post(initURL, "application/xml", nil)
	if err != nil {
		return fmt.Errorf("CreateMPU: %w", err)
	}
	defer initResp.Body.Close()
	initBody, _ := io.ReadAll(initResp.Body)
	if initResp.StatusCode != http.StatusOK {
		return fmt.Errorf("CreateMPU: status %d: %s", initResp.StatusCode, string(initBody))
	}

	var initResult struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		UploadID string   `xml:"UploadId"`
	}
	if err := xml.Unmarshal(initBody, &initResult); err != nil {
		return fmt.Errorf("CreateMPU: parse: %w", err)
	}
	uploadID := initResult.UploadID

	// Cleanup: abort on failure.
	abortOnErr := true
	defer func() {
		if abortOnErr {
			abortURL := fmt.Sprintf("%s/%s/%s?uploadId=%s", gw.URL, bucket, key, uploadID)
			abortReq, _ := http.NewRequest("DELETE", abortURL, nil)
			abortResp, err := client.Do(abortReq)
			if err == nil {
				io.Copy(io.Discard, abortResp.Body)
				abortResp.Body.Close()
			}
		}
	}()

	// 2. UploadPart × len(parts)
	type partInfo struct {
		number int
		etag   string
	}
	var uploadedParts []partInfo

	for i, data := range parts {
		partNum := i + 1
		partURL := fmt.Sprintf("%s/%s/%s?partNumber=%d&uploadId=%s",
			gw.URL, bucket, key, partNum, uploadID)
		partReq, _ := http.NewRequest("PUT", partURL, bytes.NewReader(data))
		partResp, err := client.Do(partReq)
		if err != nil {
			return fmt.Errorf("UploadPart %d: %w", partNum, err)
		}
		partBody, _ := io.ReadAll(partResp.Body)
		partResp.Body.Close()
		if partResp.StatusCode != http.StatusOK {
			return fmt.Errorf("UploadPart %d: status %d: %s", partNum, partResp.StatusCode, string(partBody))
		}
		uploadedParts = append(uploadedParts, partInfo{
			number: partNum,
			etag:   partResp.Header.Get("ETag"),
		})
	}

	// 3. CompleteMultipartUpload
	var xmlBuf bytes.Buffer
	xmlBuf.WriteString("<CompleteMultipartUpload>")
	for _, p := range uploadedParts {
		fmt.Fprintf(&xmlBuf, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>",
			p.number, p.etag)
	}
	xmlBuf.WriteString("</CompleteMultipartUpload>")

	completeURL := fmt.Sprintf("%s/%s/%s?uploadId=%s", gw.URL, bucket, key, uploadID)
	completeReq, _ := http.NewRequest("POST", completeURL, &xmlBuf)
	completeReq.Header.Set("Content-Type", "application/xml")
	completeResp, err := client.Do(completeReq)
	if err != nil {
		return fmt.Errorf("CompleteMPU: %w", err)
	}
	completeBody, _ := io.ReadAll(completeResp.Body)
	completeResp.Body.Close()
	if completeResp.StatusCode != http.StatusOK {
		return fmt.Errorf("CompleteMPU: status %d: %s", completeResp.StatusCode, string(completeBody))
	}

	abortOnErr = false
	return nil
}
