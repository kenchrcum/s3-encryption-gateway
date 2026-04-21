//go:build conformance

package conformance

// Load / soak tests — tier-2, provider-agnostic, environment-variable driven.
//
// The same test functions serve two roles:
//
//   make test-load       — CI gate: small objects, short run, fast feedback.
//   make test-load-soak  — Full soak: large objects, long run, stress testing.
//
// The difference is controlled exclusively by environment variables — no
// separate binary, no shell script, no pre-running gateway.  Testcontainers
// brings up MinIO (or Garage) and the in-process harness runs the gateway.
//
// Env vars (all optional; CI defaults are used when unset):
//
//	SOAK_WORKERS      int           workers (goroutines)           default: 3  / soak: 10
//	SOAK_DURATION     duration str  test duration                  default: 5s / soak: 60s
//	SOAK_QPS          int           requests per second per worker default: 10 / soak: 25
//	SOAK_OBJECT_SIZE  int (bytes)   object size                    default: 102400  / soak: 52428800 (50 MiB)
//	SOAK_CHUNK_SIZE   int (bytes)   encryption chunk size          default: 65536
//	SOAK_PART_SIZE    int (bytes)   multipart part size (≥5 MiB)  default: 5242880

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kenneth/s3-encryption-gateway/test/harness"
	"github.com/kenneth/s3-encryption-gateway/test/provider"
)

// ── Parameter resolution ────────────────────────────────────────────────────

// loadTestParams holds the tunable knobs for the in-conformance load runner.
type loadTestParams struct {
	workers    int
	duration   time.Duration
	qps        int   // requests per second per worker
	objectSize int64 // bytes
	chunkSize  int64 // encryption chunk size (bytes)
	partSize   int64 // multipart part size (bytes; S3 requires ≥ 5 MiB for all but last)
}

// resolveLoadParams reads environment variables and applies them on top of the
// supplied CI defaults. Unknown / malformed values are silently ignored and the
// default is kept, which is the safe choice for CI.
func resolveLoadParams(ci loadTestParams) loadTestParams {
	p := ci // copy
	if v := envInt("SOAK_WORKERS"); v > 0 {
		p.workers = v
	}
	if v := envDuration("SOAK_DURATION"); v > 0 {
		p.duration = v
	}
	if v := envInt("SOAK_QPS"); v > 0 {
		p.qps = v
	}
	if v := envInt64("SOAK_OBJECT_SIZE"); v > 0 {
		p.objectSize = v
	}
	if v := envInt64("SOAK_CHUNK_SIZE"); v > 0 {
		p.chunkSize = v
	}
	if v := envInt64("SOAK_PART_SIZE"); v > 0 {
		p.partSize = v
	}
	return p
}

// ciLoadParams are the defaults used when no env vars are set — sized for
// fast CI feedback (< 10 s per test).
func ciLoadParams() loadTestParams {
	return resolveLoadParams(loadTestParams{
		workers:    3,
		duration:   5 * time.Second,
		qps:        10,
		objectSize: 100 * 1024,      // 100 KiB
		chunkSize:  64 * 1024,       // 64 KiB
		partSize:   5 * 1024 * 1024, // 5 MiB — S3 minimum
	})
}

// logParams writes a one-line parameter summary to t.Log.
func logParams(t *testing.T, label string, p loadTestParams) {
	t.Helper()
	t.Logf("%s params: workers=%d duration=%s qps=%d object=%s chunk=%s part=%s",
		label, p.workers, p.duration,
		p.qps,
		humanBytes(p.objectSize),
		humanBytes(p.chunkSize),
		humanBytes(p.partSize),
	)
}

func humanBytes(b int64) string {
	switch {
	case b >= 1024*1024:
		return fmt.Sprintf("%d MiB", b/1024/1024)
	case b >= 1024:
		return fmt.Sprintf("%d KiB", b/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// ── Shared results counter ──────────────────────────────────────────────────

// loadResults is a minimal atomic counter struct shared across goroutines.
type loadResults struct {
	total   int64
	success int64
	failed  int64
}

// ── Range load test ─────────────────────────────────────────────────────────

// testRangeLoad runs concurrent range GET requests against a single shared
// encrypted object. It cycles through six scenarios:
//   - first 1 KiB (bytes=0-1023)
//   - last 1 KiB
//   - suffix 512 B (bytes=-512)
//   - cross-chunk boundary
//   - large range (25 %–50 % of object)
//   - deliberately invalid range → must return HTTP 416
//
// The test asserts zero failures across all workers for the full duration.
// Parameters are read from env vars (see file header); CI defaults are small.
func testRangeLoad(t *testing.T, inst provider.Instance) {
	t.Helper()
	p := ciLoadParams()
	logParams(t, "RangeLoad", p)

	gw := harness.StartGateway(t, inst)

	// Upload the single shared object that all workers read.
	objectKey := uniqueKey(t)
	put(t, gw, inst.Bucket, objectKey, bytes.Repeat([]byte("R"), int(p.objectSize)))

	type rangeCase struct {
		header       string
		expectedCode int
	}
	cases := []rangeCase{
		{"bytes=0-1023", http.StatusPartialContent},
		{fmt.Sprintf("bytes=%d-%d", p.objectSize-1024, p.objectSize-1), http.StatusPartialContent},
		{"bytes=-512", http.StatusPartialContent},
		{fmt.Sprintf("bytes=%d-%d", p.chunkSize/2, p.chunkSize/2+1023), http.StatusPartialContent},
		{fmt.Sprintf("bytes=%d-%d", p.objectSize/4, p.objectSize/2), http.StatusPartialContent},
		{"bytes=999999999-1000000000", http.StatusRequestedRangeNotSatisfiable},
	}

	var res loadResults
	runWorkers(t, p, func(workerID int, idx int64, client *http.Client) {
		rc := cases[idx%int64(len(cases))]
		req, err := http.NewRequest("GET", objectURL(gw, inst.Bucket, objectKey), nil)
		if err != nil {
			atomic.AddInt64(&res.failed, 1)
			return
		}
		req.Header.Set("Range", rc.header)

		resp, err := client.Do(req)
		atomic.AddInt64(&res.total, 1)
		if err != nil {
			atomic.AddInt64(&res.failed, 1)
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode == rc.expectedCode {
			atomic.AddInt64(&res.success, 1)
		} else {
			atomic.AddInt64(&res.failed, 1)
		}
	})

	reportResults(t, "RangeLoad", p, &res)
}

// ── Multipart load test ─────────────────────────────────────────────────────

// testMultipartLoad runs concurrent full multipart uploads using the real S3
// multipart protocol (CreateMPU → UploadPart × 2 → CompleteMPU).
// Each worker generates a unique key per upload so there is no key collision.
// The test asserts zero failures across all workers for the full duration.
func testMultipartLoad(t *testing.T, inst provider.Instance) {
	t.Helper()
	p := ciLoadParams()
	logParams(t, "MultipartLoad", p)

	gw := harness.StartGateway(t, inst)

	// Pre-allocate part data slices (shared across goroutines; read-only).
	part1 := bytes.Repeat([]byte("P"), int(p.partSize))
	part2 := []byte("tail") // last part may be < 5 MiB

	var res loadResults
	runWorkers(t, p, func(workerID int, idx int64, client *http.Client) {
		key := fmt.Sprintf("mpu-load/w%d/%d-%d", workerID, time.Now().UnixNano(), idx)
		atomic.AddInt64(&res.total, 1)
		if err := doFullMPU(gw, inst.Bucket, key, client, part1, part2); err != nil {
			t.Logf("MPU worker %d: %v", workerID, err)
			atomic.AddInt64(&res.failed, 1)
		} else {
			atomic.AddInt64(&res.success, 1)
		}
	})

	reportResults(t, "MultipartLoad", p, &res)
}

// ── Shared worker harness ────────────────────────────────────────────────────

// workFn is called by each worker tick. workerID is 0-based; idx is a
// per-worker monotonically increasing counter; client is a fresh-ish HTTP
// client (shared per worker, not per request).
type workFn func(workerID int, idx int64, client *http.Client)

// runWorkers starts p.workers goroutines, each ticking at p.qps for p.duration,
// calling fn on every tick. It blocks until all workers finish.
func runWorkers(t *testing.T, p loadTestParams, fn workFn) {
	t.Helper()
	interval := time.Second / time.Duration(p.qps)
	if interval <= 0 {
		interval = time.Millisecond
	}

	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	for w := 0; w < p.workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			client := &http.Client{Timeout: 120 * time.Second}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			var idx int64
			for {
				select {
				case <-stopCh:
					return
				case <-ticker.C:
					fn(workerID, idx, client)
					idx++
				}
			}
		}(w)
	}

	time.Sleep(p.duration)
	close(stopCh)
	wg.Wait()
}

// reportResults logs a summary and asserts the pass criteria.
func reportResults(t *testing.T, label string, p loadTestParams, res *loadResults) {
	t.Helper()
	throughput := float64(res.total) / p.duration.Seconds()
	t.Logf("%s: total=%d success=%d failed=%d throughput=%.1f req/s",
		label, res.total, res.success, res.failed, throughput)

	if res.total == 0 {
		t.Errorf("%s: no requests were issued", label)
	}
	if res.failed > 0 {
		t.Errorf("%s: %d/%d requests failed", label, res.failed, res.total)
	}
}

// ── Full MPU helper ─────────────────────────────────────────────────────────

// doFullMPU performs a complete S3 multipart upload: CreateMPU → UploadPart×N
// → CompleteMPU. It uses the supplied client so callers control concurrency.
func doFullMPU(gw *harness.Gateway, bucket, key string, client *http.Client, parts ...[]byte) error {
	// 1. CreateMultipartUpload
	initURL := fmt.Sprintf("%s/%s/%s?uploads", gw.URL, bucket, key)
	initResp, err := client.Post(initURL, "application/xml", nil)
	if err != nil {
		return fmt.Errorf("CreateMPU: %w", err)
	}
	initBody, _ := io.ReadAll(initResp.Body)
	initResp.Body.Close()
	if initResp.StatusCode != http.StatusOK {
		return fmt.Errorf("CreateMPU: status %d: %s", initResp.StatusCode, string(initBody))
	}

	var initResult struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		UploadID string   `xml:"UploadId"`
	}
	if err := xml.Unmarshal(initBody, &initResult); err != nil {
		return fmt.Errorf("CreateMPU parse: %w", err)
	}
	uploadID := initResult.UploadID

	// Abort on any subsequent error.
	type pInfo struct{ num int; etag string }
	var uploaded []pInfo
	abort := func() {
		u := fmt.Sprintf("%s/%s/%s?uploadId=%s", gw.URL, bucket, key, uploadID)
		req, _ := http.NewRequest("DELETE", u, nil)
		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}

	// 2. UploadPart × N
	for i, data := range parts {
		partNum := i + 1
		pURL := fmt.Sprintf("%s/%s/%s?partNumber=%d&uploadId=%s",
			gw.URL, bucket, key, partNum, uploadID)
		pReq, _ := http.NewRequest("PUT", pURL, bytes.NewReader(data))
		pResp, err := client.Do(pReq)
		if err != nil {
			abort()
			return fmt.Errorf("UploadPart %d: %w", partNum, err)
		}
		pBody, _ := io.ReadAll(pResp.Body)
		pResp.Body.Close()
		if pResp.StatusCode != http.StatusOK {
			abort()
			return fmt.Errorf("UploadPart %d: status %d: %s", partNum, pResp.StatusCode, string(pBody))
		}
		uploaded = append(uploaded, pInfo{partNum, pResp.Header.Get("ETag")})
	}

	// 3. CompleteMultipartUpload
	var xmlBuf bytes.Buffer
	xmlBuf.WriteString("<CompleteMultipartUpload>")
	for _, p := range uploaded {
		fmt.Fprintf(&xmlBuf, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>",
			p.num, p.etag)
	}
	xmlBuf.WriteString("</CompleteMultipartUpload>")

	cURL := fmt.Sprintf("%s/%s/%s?uploadId=%s", gw.URL, bucket, key, uploadID)
	cReq, _ := http.NewRequest("POST", cURL, &xmlBuf)
	cReq.Header.Set("Content-Type", "application/xml")
	cResp, err := client.Do(cReq)
	if err != nil {
		abort()
		return fmt.Errorf("CompleteMPU: %w", err)
	}
	cBody, _ := io.ReadAll(cResp.Body)
	cResp.Body.Close()
	if cResp.StatusCode != http.StatusOK {
		return fmt.Errorf("CompleteMPU: status %d: %s", cResp.StatusCode, string(cBody))
	}
	return nil
}

// ── Env-var helpers ─────────────────────────────────────────────────────────

func envInt(key string) int {
	v, _ := strconv.Atoi(os.Getenv(key))
	return v
}

func envInt64(key string) int64 {
	v, _ := strconv.ParseInt(os.Getenv(key), 10, 64)
	return v
}

func envDuration(key string) time.Duration {
	d, _ := time.ParseDuration(os.Getenv(key))
	return d
}
