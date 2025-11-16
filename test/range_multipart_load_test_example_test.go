package test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// TestRangeLoadTestExample demonstrates how to run range load tests with baseline tracking.
func ExampleRunRangeLoadTest() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	// Configuration for range load testing
	config := RangeLoadTestConfig{
		GatewayURL:          "http://localhost:8080",
		NumWorkers:          10,
		Duration:            30 * time.Second,
		QPS:                 50,   // 50 requests per second total
		ObjectSize:          100 * 1024 * 1024, // 100MB test objects
		ChunkSize:           64 * 1024,         // 64KB encryption chunks
		BaselineFile:        "testdata/baselines/range_load_test_baseline.json",
		RegressionThreshold: 10.0, // 10% regression threshold
	}

	fmt.Println("Running range load test...")
	results, err := RunRangeLoadTest(config, logger)
	if err != nil {
		fmt.Printf("Range load test failed: %v\n", err)
		return
	}

	PrintLoadTestResults(results)

	// Check for regressions
	if config.BaselineFile != "" {
		regression, err := AnalyzeRegression(results, config.BaselineFile, config.RegressionThreshold)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("No baseline found - this run establishes the baseline\n")
			} else {
				fmt.Printf("Failed to analyze regression: %v\n", err)
			}
		} else {
			PrintRegressionResult(regression)
		}
	}
}

// TestMultipartLoadTestExample demonstrates how to run multipart load tests with baseline tracking.
func ExampleRunMultipartLoadTest() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	// Configuration for multipart load testing
	config := MultipartLoadTestConfig{
		GatewayURL:          "http://localhost:8080",
		NumWorkers:          5,
		Duration:            60 * time.Second,
		QPS:                 10,   // 10 multipart uploads per second total
		ObjectSize:          500 * 1024 * 1024, // 500MB test objects
		PartSize:            100 * 1024 * 1024, // 100MB parts
		BaselineFile:        "testdata/baselines/multipart_load_test_baseline.json",
		RegressionThreshold: 15.0, // 15% regression threshold
	}

	fmt.Println("Running multipart load test...")
	results, err := RunMultipartLoadTest(config, logger)
	if err != nil {
		fmt.Printf("Multipart load test failed: %v\n", err)
		return
	}

	PrintLoadTestResults(results)

	// Check for regressions
	if config.BaselineFile != "" {
		regression, err := AnalyzeRegression(results, config.BaselineFile, config.RegressionThreshold)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("No baseline found - this run establishes the baseline\n")
			} else {
				fmt.Printf("Failed to analyze regression: %v\n", err)
			}
		} else {
			PrintRegressionResult(regression)
		}
	}
}

// TestRunLoadTests demonstrates running both range and multipart tests.
func TestRunLoadTests(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	// Create baseline directory
	baselineDir := "testdata/baselines"
	if err := os.MkdirAll(baselineDir, 0755); err != nil {
		fmt.Printf("Failed to create baseline directory: %v\n", err)
		return
	}

	fmt.Println("=== Running Comprehensive Load Test Suite ===")

	// Range load test
	fmt.Println("1. Running Range Load Test")
	rangeConfig := RangeLoadTestConfig{
		GatewayURL:          "http://localhost:8080",
		NumWorkers:          8,
		Duration:            45 * time.Second,
		QPS:                 40,
		ObjectSize:          50 * 1024 * 1024, // 50MB
		ChunkSize:           64 * 1024,        // 64KB chunks
		BaselineFile:        filepath.Join(baselineDir, "range_load_test_baseline.json"),
		RegressionThreshold: 10.0,
	}

	rangeResults, err := RunRangeLoadTest(rangeConfig, logger)
	if err != nil {
		fmt.Printf("Range load test failed: %v\n", err)
		return
	}

	// Multipart load test
	fmt.Println("\n2. Running Multipart Load Test")
	multipartConfig := MultipartLoadTestConfig{
		GatewayURL:          "http://localhost:8080",
		NumWorkers:          4,
		Duration:            90 * time.Second,
		QPS:                 5,
		ObjectSize:          200 * 1024 * 1024, // 200MB
		PartSize:            50 * 1024 * 1024,  // 50MB parts
		BaselineFile:        filepath.Join(baselineDir, "multipart_load_test_baseline.json"),
		RegressionThreshold: 15.0,
	}

	multipartResults, err := RunMultipartLoadTest(multipartConfig, logger)
	if err != nil {
		fmt.Printf("Multipart load test failed: %v\n", err)
		return
	}

	// Print comprehensive results
	fmt.Println("\n=== Suite Summary ===")

	fmt.Printf("Range Test Results:\n")
	fmt.Printf("  Throughput: %.2f req/s\n", rangeResults.Throughput)
	fmt.Printf("  P95 Latency: %v\n", rangeResults.P95Latency)
	fmt.Printf("  Error Rate: %.2f%%\n", rangeResults.ErrorRate*100)
	if rangeResults.RangeSpecific != nil {
		fmt.Printf("  Range Types - First: %d, Last: %d, Cross-chunk: %d\n",
			rangeResults.RangeSpecific.FirstByteRanges,
			rangeResults.RangeSpecific.LastByteRanges,
			rangeResults.RangeSpecific.CrossChunkRanges)
	}

	fmt.Printf("\nMultipart Test Results:\n")
	fmt.Printf("  Throughput: %.2f req/s\n", multipartResults.Throughput)
	fmt.Printf("  P95 Latency: %v\n", multipartResults.P95Latency)
	fmt.Printf("  Error Rate: %.2f%%\n", multipartResults.ErrorRate*100)
	if multipartResults.MultipartSpecific != nil {
		fmt.Printf("  Total Uploads: %d\n", multipartResults.MultipartSpecific.TotalUploads)
		fmt.Printf("  Avg Part Size: %d MB\n", multipartResults.MultipartSpecific.AvgPartSize/(1024*1024))
	}

	// Check for regressions
	fmt.Println("\n=== Regression Analysis ===")

	checkRegression("Range Load Test", rangeResults, rangeConfig.BaselineFile, rangeConfig.RegressionThreshold)
	checkRegression("Multipart Load Test", multipartResults, multipartConfig.BaselineFile, multipartConfig.RegressionThreshold)

	fmt.Println("\n=== Load Test Suite Complete ===")
}

// checkRegression analyzes regression for a test and prints results.
func checkRegression(testName string, results *LoadTestMetrics, baselineFile string, threshold float64) {
	regression, err := AnalyzeRegression(results, baselineFile, threshold)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("%s: No baseline found - establishing baseline\n", testName)
		} else {
			fmt.Printf("%s: Failed to analyze regression: %v\n", testName, err)
		}
		return
	}

	fmt.Printf("%s Regression Results:\n", testName)
	if regression.SignificantRegression {
		fmt.Printf("  ⚠️  SIGNIFICANT REGRESSION DETECTED\n")
	} else {
		fmt.Printf("  ✅ No significant regression\n")
	}

	fmt.Printf("  Latency change: %.2f%%\n", regression.LatencyRegression)
	fmt.Printf("  Throughput change: %.2f%%\n", regression.ThroughputRegression)
	fmt.Printf("  Error rate change: %.2f%%\n", regression.ErrorRateRegression)

	if len(regression.Details) > 0 {
		fmt.Printf("  Details:\n")
		for _, detail := range regression.Details {
			fmt.Printf("    - %s\n", detail)
		}
	}
}

// TestRunLoadTestWithPrometheus demonstrates integration with Prometheus metrics.
func TestRunLoadTestWithPrometheus(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	// This example shows how to integrate with Prometheus for additional metrics
	config := RangeLoadTestConfig{
		GatewayURL:          "http://localhost:8080",
		NumWorkers:          5,
		Duration:            30 * time.Second,
		QPS:                 25,
		ObjectSize:          10 * 1024 * 1024, // 10MB
		ChunkSize:           64 * 1024,        // 64KB chunks
		BaselineFile:        "testdata/baselines/range_prometheus_test_baseline.json",
		RegressionThreshold: 10.0,
	}

	startTime := time.Now()

	fmt.Println("Running range load test with Prometheus metrics...")
	results, err := RunRangeLoadTest(config, logger)
	if err != nil {
		fmt.Printf("Range load test failed: %v\n", err)
		return
	}

	endTime := time.Now()

	PrintLoadTestResults(results)

	// Query Prometheus for additional metrics (requires Prometheus running)
	prometheusURL := "http://localhost:9090" // Default Prometheus address
	promMetrics, err := QueryPrometheusMetrics(prometheusURL, startTime, endTime)
	if err != nil {
		fmt.Printf("Failed to query Prometheus metrics: %v\n", err)
		fmt.Println("Note: This requires Prometheus to be running and configured")
		return
	}

	fmt.Println("\n=== Prometheus Metrics During Test ===")
	for metric, value := range promMetrics {
		fmt.Printf("%s: %v\n", metric, value)
	}

	fmt.Println("\nNote: Prometheus metrics provide additional system-level insights")
}

// BenchmarkRangeLoadTest provides a benchmark for range operations.
func BenchmarkRangeLoadTest(b *testing.B) {
	// This would be used for Go benchmarking integration
	// For now, it's a placeholder showing the structure

	config := RangeLoadTestConfig{
		GatewayURL: "http://localhost:8080",
		NumWorkers: 2,
		Duration:   5 * time.Second,
		QPS:        10,
		ObjectSize: 1 * 1024 * 1024, // 1MB for quick benchmarks
		ChunkSize:  64 * 1024,       // 64KB chunks
	}

	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel) // Reduce log noise during benchmarks

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := RunRangeLoadTest(config, logger)
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}

// BenchmarkMultipartLoadTest provides a benchmark for multipart operations.
func BenchmarkMultipartLoadTest(b *testing.B) {
	config := MultipartLoadTestConfig{
		GatewayURL: "http://localhost:8080",
		NumWorkers: 1,
		Duration:   5 * time.Second,
		QPS:        2,
		ObjectSize: 10 * 1024 * 1024, // 10MB for reasonable benchmark time
		PartSize:   5 * 1024 * 1024,  // 5MB parts
	}

	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := RunMultipartLoadTest(config, logger)
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}
