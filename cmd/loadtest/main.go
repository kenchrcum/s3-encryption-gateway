package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/kenneth/s3-encryption-gateway/test"
)

func main() {
	var (
		gatewayURL    = flag.String("gateway-url", "http://localhost:8080", "S3 Encryption Gateway URL")
		testType      = flag.String("test-type", "both", "Test type: range, multipart, or both")
		duration      = flag.Duration("duration", 30*time.Second, "Test duration")
		workers       = flag.Int("workers", 5, "Number of worker goroutines")
		qps           = flag.Int("qps", 25, "Queries per second per worker")
		objectSize    = flag.Int64("object-size", 50*1024*1024, "Object size in bytes (50MB default)")
		chunkSize     = flag.Int64("chunk-size", 64*1024, "Encryption chunk size (64KB default)")
		partSize      = flag.Int64("part-size", 10*1024*1024, "Multipart part size (10MB default)")
		baselineDir   = flag.String("baseline-dir", "testdata/baselines", "Directory for baseline files")
		threshold     = flag.Float64("threshold", 10.0, "Regression threshold percentage")
		prometheusURL    = flag.String("prometheus-url", "", "Prometheus URL for additional metrics")
		verbose          = flag.Bool("verbose", false, "Enable verbose logging")
		updateBaseline   = flag.Bool("update-baseline", false, "Update baseline files instead of checking regression")
		manageMinIO      = flag.Bool("manage-minio", false, "Automatically start/stop MinIO test environment")
		minioComposeFile = flag.String("minio-compose", "test/docker-compose.yml", "Path to MinIO docker-compose file")
	)

	flag.Parse()

	// Setup logging (before MinIO management)
	logger := logrus.New()
	if *verbose {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	// Manage MinIO environment if requested
	if *manageMinIO {
		if err := startMinIOEnvironment(*minioComposeFile, logger); err != nil {
			log.Fatalf("Failed to start MinIO environment: %v", err)
		}
		defer func() {
			if err := stopMinIOEnvironment(*minioComposeFile, logger); err != nil {
				log.Printf("Warning: Failed to stop MinIO environment: %v", err)
			}
		}()
	}

	// Ensure baseline directory exists
	if err := os.MkdirAll(*baselineDir, 0755); err != nil {
		log.Fatalf("Failed to create baseline directory: %v", err)
	}

	fmt.Println("=== S3 Encryption Gateway Load Test Runner ===")
	fmt.Printf("Gateway URL: %s\n", *gatewayURL)
	fmt.Printf("Test Type: %s\n", *testType)
	fmt.Printf("Duration: %v\n", *duration)
	fmt.Printf("Workers: %d\n", *workers)
	fmt.Printf("QPS per Worker: %d\n", *qps)
	fmt.Printf("Regression Threshold: %.1f%%\n", *threshold)
	if *prometheusURL != "" {
		fmt.Printf("Prometheus URL: %s\n", *prometheusURL)
	}
	fmt.Println()

	var exitCode int
	startTime := time.Now()

	// Run range tests
	if *testType == "range" || *testType == "both" {
		fmt.Println("--- Running Range Load Test ---")
		if err := runRangeTest(*gatewayURL, *workers, *duration, *qps, *objectSize, *chunkSize,
			*baselineDir, *threshold, *prometheusURL, *updateBaseline, logger); err != nil {
			log.Printf("Range test failed: %v", err)
			exitCode = 1
		}
		fmt.Println()
	}

	// Run multipart tests
	if *testType == "multipart" || *testType == "both" {
		fmt.Println("--- Running Multipart Load Test ---")
		if err := runMultipartTest(*gatewayURL, *workers, *duration, *qps, *objectSize, *partSize,
			*baselineDir, *threshold, *prometheusURL, *updateBaseline, logger); err != nil {
			log.Printf("Multipart test failed: %v", err)
			exitCode = 1
		}
		fmt.Println()
	}

	totalDuration := time.Since(startTime)
	fmt.Printf("=== Load Tests Complete (Total Time: %v) ===\n", totalDuration)

	if exitCode != 0 {
		fmt.Println("❌ Some tests failed or regressions detected")
		os.Exit(exitCode)
	} else {
		fmt.Println("✅ All tests passed")
	}
}

func runRangeTest(gatewayURL string, workers int, duration time.Duration, qps int,
	objectSize, chunkSize int64, baselineDir string, threshold float64,
	prometheusURL string, updateBaseline bool, logger *logrus.Logger) error {

	config := test.RangeLoadTestConfig{
		GatewayURL:          gatewayURL,
		NumWorkers:          workers,
		Duration:            duration,
		QPS:                 qps,
		ObjectSize:          objectSize,
		ChunkSize:           chunkSize,
		BaselineFile:        filepath.Join(baselineDir, "range_load_test_baseline.json"),
		RegressionThreshold: threshold,
	}

	var startTime time.Time
	if prometheusURL != "" {
		startTime = time.Now()
	}

	results, err := test.RunRangeLoadTest(config, logger)
	if err != nil {
		return fmt.Errorf("range load test failed: %w", err)
	}

	test.PrintLoadTestResults(results)

	// Query Prometheus if configured
	if prometheusURL != "" {
		endTime := time.Now()
		promMetrics, err := test.QueryPrometheusMetrics(prometheusURL, startTime, endTime)
		if err != nil {
			logger.WithError(err).Warn("Failed to query Prometheus metrics")
		} else {
			fmt.Println("--- Prometheus Metrics ---")
			for metric, value := range promMetrics {
				fmt.Printf("%s: %v\n", metric, value)
			}
			fmt.Println()
		}
	}

	// Handle baseline/regression logic
	if updateBaseline {
		fmt.Println("✅ Baseline updated for range load test")
		return nil
	}

	regression, err := test.AnalyzeRegression(results, config.BaselineFile, config.RegressionThreshold)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("ℹ️  No baseline found - run with --update-baseline to create one")
			return nil
		}
		return fmt.Errorf("regression analysis failed: %w", err)
	}

	test.PrintRegressionResult(regression)

	if regression.SignificantRegression {
		return fmt.Errorf("significant regression detected in range load test")
	}

	fmt.Println("✅ Range load test passed")
	return nil
}

func runMultipartTest(gatewayURL string, workers int, duration time.Duration, qps int,
	objectSize, partSize int64, baselineDir string, threshold float64,
	prometheusURL string, updateBaseline bool, logger *logrus.Logger) error {

	config := test.MultipartLoadTestConfig{
		GatewayURL:          gatewayURL,
		NumWorkers:          workers,
		Duration:            duration,
		QPS:                 qps,
		ObjectSize:          objectSize,
		PartSize:            partSize,
		BaselineFile:        filepath.Join(baselineDir, "multipart_load_test_baseline.json"),
		RegressionThreshold: threshold,
	}

	var startTime time.Time
	if prometheusURL != "" {
		startTime = time.Now()
	}

	results, err := test.RunMultipartLoadTest(config, logger)
	if err != nil {
		return fmt.Errorf("multipart load test failed: %w", err)
	}

	test.PrintLoadTestResults(results)

	// Query Prometheus if configured
	if prometheusURL != "" {
		endTime := time.Now()
		promMetrics, err := test.QueryPrometheusMetrics(prometheusURL, startTime, endTime)
		if err != nil {
			logger.WithError(err).Warn("Failed to query Prometheus metrics")
		} else {
			fmt.Println("--- Prometheus Metrics ---")
			for metric, value := range promMetrics {
				fmt.Printf("%s: %v\n", metric, value)
			}
			fmt.Println()
		}
	}

	// Handle baseline/regression logic
	if updateBaseline {
		fmt.Println("✅ Baseline updated for multipart load test")
		return nil
	}

	regression, err := test.AnalyzeRegression(results, config.BaselineFile, config.RegressionThreshold)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("ℹ️  No baseline found - run with --update-baseline to create one")
			return nil
		}
		return fmt.Errorf("regression analysis failed: %w", err)
	}

	test.PrintRegressionResult(regression)

	if regression.SignificantRegression {
		return fmt.Errorf("significant regression detected in multipart load test")
	}

	fmt.Println("✅ Multipart load test passed")
	return nil
}

// startMinIOEnvironment starts the MinIO test environment using docker-compose.
func startMinIOEnvironment(composeFile string, logger *logrus.Logger) error {
	logger.Info("Starting MinIO test environment...")

	// Check if docker-compose file exists
	if _, err := os.Stat(composeFile); os.IsNotExist(err) {
		return fmt.Errorf("docker-compose file not found: %s", composeFile)
	}

	// Get the directory containing the compose file
	composeDir := filepath.Dir(composeFile)
	composeFileName := filepath.Base(composeFile)

	// Stop any existing containers first (cleanup)
	stopCmd := exec.Command("docker-compose", "-f", composeFileName, "down", "-v")
	stopCmd.Dir = composeDir
	if err := stopCmd.Run(); err != nil {
		logger.WithError(err).Warn("Failed to stop existing MinIO containers (this is usually OK)")
	}

	// Start the MinIO environment
	logger.Info("Starting MinIO containers...")
	startCmd := exec.Command("docker-compose", "-f", composeFileName, "up", "-d")
	startCmd.Dir = composeDir

	if output, err := startCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start MinIO environment: %v\nOutput: %s", err, string(output))
	}

	// Wait for MinIO to be healthy
	logger.Info("Waiting for MinIO to become healthy...")
	if err := waitForMinIOHealthy(composeDir, composeFileName, logger); err != nil {
		return fmt.Errorf("MinIO failed to become healthy: %v", err)
	}

	logger.Info("✅ MinIO test environment is ready")
	return nil
}

// stopMinIOEnvironment stops the MinIO test environment using docker-compose.
func stopMinIOEnvironment(composeFile string, logger *logrus.Logger) error {
	logger.Info("Stopping MinIO test environment...")

	// Check if docker-compose file exists
	if _, err := os.Stat(composeFile); os.IsNotExist(err) {
		logger.Warn("Docker-compose file not found, assuming environment already stopped")
		return nil
	}

	// Get the directory containing the compose file
	composeDir := filepath.Dir(composeFile)
	composeFileName := filepath.Base(composeFile)

	// Stop the MinIO environment
	stopCmd := exec.Command("docker-compose", "-f", composeFileName, "down", "-v")
	stopCmd.Dir = composeDir

	if output, err := stopCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stop MinIO environment: %v\nOutput: %s", err, string(output))
	}

	logger.Info("✅ MinIO test environment stopped")
	return nil
}

// waitForMinIOHealthy waits for MinIO to be ready and healthy.
func waitForMinIOHealthy(composeDir, composeFile string, logger *logrus.Logger) error {
	maxRetries := 30 // 30 * 5s = 150s max wait time
	retryCount := 0

	for retryCount < maxRetries {
		// Check if MinIO container is running
		psCmd := exec.Command("docker-compose", "-f", composeFile, "ps", "minio")
		psCmd.Dir = composeDir
		output, err := psCmd.Output()
		if err != nil {
			logger.WithError(err).Debug("Failed to check MinIO container status")
		} else if !bytes.Contains(output, []byte("Up")) {
			logger.Debug("MinIO container is not running yet")
		} else {
			// Container is running, now check health
			logger.Debug("Checking MinIO health endpoint...")
			if checkMinIOHealth() {
				logger.Info("MinIO is healthy and ready")
				return nil
			}
			logger.Debug("MinIO health check failed, container may not be ready yet")
		}

		retryCount++
		logger.WithField("attempt", retryCount).WithField("max", maxRetries).Debug("Waiting for MinIO to be ready...")
		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("MinIO did not become healthy within %d attempts", maxRetries)
}

// checkMinIOHealth checks if MinIO is responding to health requests.
func checkMinIOHealth() bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("http://localhost:9000/minio/health/live")
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}
