package test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// LoadTestConfig holds configuration for load testing.
type LoadTestConfig struct {
	GatewayURL string
	NumWorkers int
	Duration   time.Duration
	QPS        int // Queries per second per worker
	ObjectSize int // Size of test objects in bytes
}

// LoadTestResults holds the results of a load test.
type LoadTestResults struct {
	TotalRequests    int64
	SuccessfulReqs   int64
	FailedReqs       int64
	TotalDuration    time.Duration
	AvgLatency       time.Duration
	MinLatency       time.Duration
	MaxLatency       time.Duration
	Throughput       float64 // requests per second
	TotalBytesSent   int64
	TotalBytesRecv   int64
}

// RunLoadTest runs a load test against the gateway.
func RunLoadTest(config LoadTestConfig, logger *logrus.Logger) (*LoadTestResults, error) {
	if logger == nil {
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
	}

	logger.WithFields(logrus.Fields{
		"workers":    config.NumWorkers,
		"duration":   config.Duration,
		"qps":        config.QPS,
		"object_size": config.ObjectSize,
	}).Info("Starting load test")

	results := &LoadTestResults{
		MinLatency: time.Hour, // Initialize with a large value
	}

	startTime := time.Now()
	var wg sync.WaitGroup
	var latencies []time.Duration
	latenciesMu := &sync.Mutex{}

	// Calculate interval between requests
	interval := time.Second / time.Duration(config.QPS)
	if interval <= 0 {
		interval = time.Millisecond
	}

	// Start workers
	stopChan := make(chan struct{})
	for i := 0; i < config.NumWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			client := &http.Client{
				Timeout: 30 * time.Second,
			}

			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			requestCount := 0
			for {
				select {
				case <-stopChan:
					return
				case <-ticker.C:
					// Perform PUT request
					objectKey := fmt.Sprintf("load-test/worker-%d/obj-%d", workerID, requestCount)
					data := make([]byte, config.ObjectSize)
					for j := range data {
						data[j] = byte(j % 256)
					}

					reqStart := time.Now()
					putURL := fmt.Sprintf("%s/test-bucket/%s", config.GatewayURL, objectKey)
					putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(data))
					if err != nil {
						atomic.AddInt64(&results.FailedReqs, 1)
						continue
					}

					resp, err := client.Do(putReq)
					latency := time.Since(reqStart)
					atomic.AddInt64(&results.TotalRequests, 1)

					if err != nil || resp.StatusCode != http.StatusOK {
						atomic.AddInt64(&results.FailedReqs, 1)
						if resp != nil {
							resp.Body.Close()
						}
					} else {
						atomic.AddInt64(&results.SuccessfulReqs, 1)
						atomic.AddInt64(&results.TotalBytesSent, int64(len(data)))
						resp.Body.Close()

						// Record latency
						latenciesMu.Lock()
						latencies = append(latencies, latency)
						if latency < results.MinLatency {
							results.MinLatency = latency
						}
						if latency > results.MaxLatency {
							results.MaxLatency = latency
						}
						latenciesMu.Unlock()
					}

					// Perform GET request
					getURL := fmt.Sprintf("%s/test-bucket/%s", config.GatewayURL, objectKey)
					getReqStart := time.Now()
					getReq, err := http.NewRequest("GET", getURL, nil)
					if err != nil {
						atomic.AddInt64(&results.FailedReqs, 1)
						continue
					}

					getResp, err := client.Do(getReq)
					getLatency := time.Since(getReqStart)
					atomic.AddInt64(&results.TotalRequests, 1)

					if err != nil || getResp.StatusCode != http.StatusOK {
						atomic.AddInt64(&results.FailedReqs, 1)
						if getResp != nil {
							getResp.Body.Close()
						}
					} else {
						atomic.AddInt64(&results.SuccessfulReqs, 1)
						n, _ := io.Copy(io.Discard, getResp.Body)
						atomic.AddInt64(&results.TotalBytesRecv, n)
						getResp.Body.Close()

						// Record latency
						latenciesMu.Lock()
						latencies = append(latencies, getLatency)
						if getLatency < results.MinLatency {
							results.MinLatency = getLatency
						}
						if getLatency > results.MaxLatency {
							results.MaxLatency = getLatency
						}
						latenciesMu.Unlock()
					}

					requestCount++
				}
			}
		}(i)
	}

	// Run for specified duration
	time.Sleep(config.Duration)
	close(stopChan)

	// Wait for all workers to finish
	wg.Wait()

	results.TotalDuration = time.Since(startTime)

	// Calculate average latency
	if len(latencies) > 0 {
		var total time.Duration
		for _, lat := range latencies {
			total += lat
		}
		results.AvgLatency = total / time.Duration(len(latencies))
	}

	// Calculate throughput
	if results.TotalDuration > 0 {
		results.Throughput = float64(results.TotalRequests) / results.TotalDuration.Seconds()
	}

	return results, nil
}

// PrintBasicLoadTestResults prints load test results in a formatted way.
func PrintBasicLoadTestResults(results *LoadTestResults) {
	fmt.Printf("\n=== Load Test Results ===\n")
	fmt.Printf("Duration: %v\n", results.TotalDuration)
	fmt.Printf("Total Requests: %d\n", results.TotalRequests)
	fmt.Printf("Successful: %d\n", results.SuccessfulReqs)
	fmt.Printf("Failed: %d\n", results.FailedReqs)
	fmt.Printf("Success Rate: %.2f%%\n", float64(results.SuccessfulReqs)/float64(results.TotalRequests)*100)
	fmt.Printf("Throughput: %.2f req/s\n", results.Throughput)
	fmt.Printf("Average Latency: %v\n", results.AvgLatency)
	fmt.Printf("Min Latency: %v\n", results.MinLatency)
	fmt.Printf("Max Latency: %v\n", results.MaxLatency)
	fmt.Printf("Total Bytes Sent: %d\n", results.TotalBytesSent)
	fmt.Printf("Total Bytes Received: %d\n", results.TotalBytesRecv)
	fmt.Printf("=======================\n\n")
}

// StreamingLoadTestConfig holds configuration for streaming-specific load tests.
type StreamingLoadTestConfig struct {
	GatewayURL    string
	NumWorkers    int
	Duration      time.Duration
	QPS           int // Queries per second per worker
	ObjectSize    int // Size of test objects in bytes
	RangeRequests bool // Enable range request testing
	MultipartTest bool // Enable multipart upload testing
}

// StreamingLoadTestResults holds results specific to streaming tests.
type StreamingLoadTestResults struct {
	LoadTestResults
	RangeRequestCount   int64
	MultipartUploadCount int64
	ContextCancellations int64
	BackpressureEvents   int64
}

// RunStreamingLoadTest runs streaming-specific load tests focusing on large objects and backpressure.
func RunStreamingLoadTest(config StreamingLoadTestConfig, logger *logrus.Logger) (*StreamingLoadTestResults, error) {
	if logger == nil {
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
	}

	logger.WithFields(logrus.Fields{
		"workers":         config.NumWorkers,
		"duration":        config.Duration,
		"qps":             config.QPS,
		"object_size":     config.ObjectSize,
		"range_requests":  config.RangeRequests,
		"multipart_tests": config.MultipartTest,
	}).Info("Starting streaming load test")

	results := &StreamingLoadTestResults{
		LoadTestResults: LoadTestResults{
			MinLatency: time.Hour, // Initialize with a large value
		},
	}

	startTime := time.Now()
	var wg sync.WaitGroup
	var latencies []time.Duration
	latenciesMu := &sync.Mutex{}

	// Calculate interval between requests
	interval := time.Second / time.Duration(config.QPS)
	if interval <= 0 {
		interval = time.Millisecond
	}

	// Start workers
	stopChan := make(chan struct{})
	for i := 0; i < config.NumWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			client := &http.Client{
				Timeout: 600 * time.Second, // 10 minutes for large objects
			}

			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			requestCount := 0
			for {
				select {
				case <-stopChan:
					return
				case <-ticker.C:
					// Generate object data
					objectKey := fmt.Sprintf("streaming-load-test/worker-%d/obj-%d", workerID, requestCount)
					data := make([]byte, config.ObjectSize)
					for j := range data {
						data[j] = byte((j + workerID + requestCount) % 256)
					}

					// Perform PUT request for large objects
					reqStart := time.Now()
					putURL := fmt.Sprintf("%s/test-bucket/%s", config.GatewayURL, objectKey)

					if config.MultipartTest && config.ObjectSize > 100*1024*1024 { // >100MB
						// Multipart upload test
						atomic.AddInt64(&results.MultipartUploadCount, 1)
						err := performMultipartUpload(client, putURL, data)
						latency := time.Since(reqStart)
						atomic.AddInt64(&results.TotalRequests, 1)

						if err != nil {
							atomic.AddInt64(&results.FailedReqs, 1)
						} else {
							atomic.AddInt64(&results.SuccessfulReqs, 1)
							atomic.AddInt64(&results.TotalBytesSent, int64(len(data)))
							recordLatency(&latencies, latenciesMu, latency, &results.LoadTestResults)
						}
					} else {
						// Regular PUT request
						putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(data))
						if err != nil {
							atomic.AddInt64(&results.FailedReqs, 1)
							continue
						}

						resp, err := client.Do(putReq)
						latency := time.Since(reqStart)
						atomic.AddInt64(&results.TotalRequests, 1)

						if err != nil || resp.StatusCode != http.StatusOK {
							atomic.AddInt64(&results.FailedReqs, 1)
							if resp != nil {
								resp.Body.Close()
							}
						} else {
							atomic.AddInt64(&results.SuccessfulReqs, 1)
							atomic.AddInt64(&results.TotalBytesSent, int64(len(data)))
							resp.Body.Close()
							recordLatency(&latencies, latenciesMu, latency, &results.LoadTestResults)
						}
					}

					// Perform GET request
					getURL := fmt.Sprintf("%s/test-bucket/%s", config.GatewayURL, objectKey)
					getReqStart := time.Now()

					var getReq *http.Request
					var err error

					if config.RangeRequests && config.ObjectSize > 1024*1024 { // >1MB
						// Range request test
						atomic.AddInt64(&results.RangeRequestCount, 1)
						rangeHeader := fmt.Sprintf("bytes=%d-%d", config.ObjectSize/4, config.ObjectSize/2)
						getReq, err = http.NewRequest("GET", getURL, nil)
						if err == nil {
							getReq.Header.Set("Range", rangeHeader)
						}
					} else {
						getReq, err = http.NewRequest("GET", getURL, nil)
					}

					if err != nil {
						atomic.AddInt64(&results.FailedReqs, 1)
						continue
					}

					getResp, err := client.Do(getReq)
					getLatency := time.Since(getReqStart)
					atomic.AddInt64(&results.TotalRequests, 1)

					if err != nil || getResp.StatusCode != http.StatusOK && getResp.StatusCode != http.StatusPartialContent {
						atomic.AddInt64(&results.FailedReqs, 1)
						if getResp != nil {
							getResp.Body.Close()
						}
					} else {
						atomic.AddInt64(&results.SuccessfulReqs, 1)
						n, _ := io.Copy(io.Discard, getResp.Body)
						atomic.AddInt64(&results.TotalBytesRecv, n)
						getResp.Body.Close()
						recordLatency(&latencies, latenciesMu, getLatency, &results.LoadTestResults)
					}

					requestCount++
				}
			}
		}(i)
	}

	// Run for specified duration
	time.Sleep(config.Duration)
	close(stopChan)

	// Wait for all workers to finish
	wg.Wait()

	results.TotalDuration = time.Since(startTime)

	// Calculate average latency
	if len(latencies) > 0 {
		var total time.Duration
		for _, lat := range latencies {
			total += lat
		}
		results.AvgLatency = total / time.Duration(len(latencies))
	}

	// Calculate throughput
	if results.TotalDuration > 0 {
		results.Throughput = float64(results.TotalRequests) / results.TotalDuration.Seconds()
	}

	return results, nil
}

// performMultipartUpload simulates a multipart upload for large objects.
func performMultipartUpload(client *http.Client, url string, data []byte) error {
	// This is a simplified multipart simulation
	// In a real implementation, this would follow S3 multipart upload protocol
	partSize := 100 * 1024 * 1024 // 100MB parts

	for offset := 0; offset < len(data); offset += partSize {
		end := offset + partSize
		if end > len(data) {
			end = len(data)
		}

		req, err := http.NewRequest("PUT", url, bytes.NewReader(data[offset:end]))
		if err != nil {
			return err
		}

		// Add part number header for simulation
		partNumber := (offset / partSize) + 1
		req.Header.Set("X-Part-Number", fmt.Sprintf("%d", partNumber))

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("part upload failed with status %d", resp.StatusCode)
		}
	}

	return nil
}

// recordLatency safely records latency measurements.
func recordLatency(latencies *[]time.Duration, mu *sync.Mutex, latency time.Duration, results *LoadTestResults) {
	mu.Lock()
	*latencies = append(*latencies, latency)
	if latency < results.MinLatency {
		results.MinLatency = latency
	}
	if latency > results.MaxLatency {
		results.MaxLatency = latency
	}
	mu.Unlock()
}

// PrintStreamingLoadTestResults prints streaming-specific load test results.
func PrintStreamingLoadTestResults(results *StreamingLoadTestResults) {
	PrintBasicLoadTestResults(&results.LoadTestResults)

	fmt.Printf("=== Streaming Test Results ===\n")
	fmt.Printf("Range Requests: %d\n", results.RangeRequestCount)
	fmt.Printf("Multipart Uploads: %d\n", results.MultipartUploadCount)
	fmt.Printf("Context Cancellations: %d\n", results.ContextCancellations)
	fmt.Printf("Backpressure Events: %d\n", results.BackpressureEvents)
	fmt.Printf("==============================\n\n")
}
