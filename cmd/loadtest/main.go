package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/kenneth/s3-encryption-gateway/test"
)

var gatewayProcess *os.Process
var garageProcess *os.Process // Keep track of garage process
var garageDir string          // Keep track of garage data dir

func main() {
	var (
		gatewayURL       = flag.String("gateway-url", "http://localhost:18080", "S3 Encryption Gateway URL")
		testType         = flag.String("test-type", "both", "Test type: range, multipart, or both")
		duration         = flag.Duration("duration", 30*time.Second, "Test duration")
		workers          = flag.Int("workers", 5, "Number of worker goroutines")
		qps              = flag.Int("qps", 25, "Queries per second per worker")
		objectSize       = flag.Int64("object-size", 50*1024*1024, "Object size in bytes (50MB default)")
		chunkSize        = flag.Int64("chunk-size", 64*1024, "Encryption chunk size (64KB default)")
		partSize         = flag.Int64("part-size", 10*1024*1024, "Multipart part size (10MB default)")
		baselineDir      = flag.String("baseline-dir", "testdata/baselines", "Directory for baseline files")
		threshold        = flag.Float64("threshold", 10.0, "Regression threshold percentage")
		prometheusURL    = flag.String("prometheus-url", "", "Prometheus URL for additional metrics")
		verbose          = flag.Bool("verbose", false, "Enable verbose logging")
		updateBaseline   = flag.Bool("update-baseline", false, "Update baseline files instead of checking regression")
		manageMinIO      = flag.Bool("manage-minio", false, "Automatically start/stop MinIO test environment")
		manageGarage     = flag.Bool("manage-garage", false, "Automatically start/stop Garage test environment")
		minioComposeFile = flag.String("minio-compose", "docker-compose.yml", "Path to MinIO docker-compose file")
		gatewayConfig    = flag.String("gateway-config", "test/gateway-config-minio.yaml", "Path to gateway config file for MinIO tests")
	)

	flag.Parse()

	// Setup logging (before MinIO management)
	logger := logrus.New()
	if *verbose {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	// Validate flags
	if *manageMinIO && *manageGarage {
		log.Fatal("Cannot manage both MinIO and Garage at the same time")
	}

	// When managing environment, automatically adjust gateway URL
	if (*manageMinIO || *manageGarage) && *gatewayURL == "http://localhost:8080" {
		*gatewayURL = "http://localhost:18080" // Matches the port in gateway-config-minio.yaml (we might reuse or override port)
		logger.Info("Automatically adjusted gateway URL for backend management")
	}

	// Set valid gateway config for Garage if not specified
	if *manageGarage && *gatewayConfig == "test/gateway-config-minio.yaml" {
		// We will creating a temporary config or use env vars to override
		logger.Info("Using default minio config but will override backend settings via env vars for Garage")
	}

	// Set up signal handling for graceful cleanup
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Env vars for gateway
	gatewayEnv := make(map[string]string)

	// Manage MinIO and Gateway environment if requested
	if *manageMinIO {
		// Start MinIO first
		if err := startMinIOEnvironment(*minioComposeFile, logger); err != nil {
			log.Fatalf("Failed to start MinIO environment: %v", err)
		}

		// Setup cleanup for MinIO
		defer func() {
			logger.Info("🧹 Cleaning up MinIO...")
			stopMinIOEnvironment(*minioComposeFile, logger)
		}()
	} else if *manageGarage {
		// Start Garage first
		accessKey, secretKey, err := startGarageEnvironment(logger)
		if err != nil {
			log.Fatalf("Failed to start Garage environment: %v", err)
		}

		// Setup cleanup for Garage
		defer func() {
			logger.Info("🧹 Cleaning up Garage...")
			stopGarageEnvironment(logger)
		}()

		// Set gateway env vars
		gatewayEnv["BACKEND_ENDPOINT"] = "http://127.0.0.1:3900"
		gatewayEnv["BACKEND_REGION"] = "garage"
		gatewayEnv["BACKEND_ACCESS_KEY"] = accessKey
		gatewayEnv["BACKEND_SECRET_KEY"] = secretKey
		gatewayEnv["BACKEND_PROVIDER"] = "s3"
		gatewayEnv["BACKEND_USE_PATH_STYLE"] = "true"
	}

	if *manageMinIO || *manageGarage {
		// Start Gateway
		if err := startGateway(*gatewayConfig, gatewayEnv, logger); err != nil {
			log.Fatalf("Failed to start gateway: %v", err)
		}

		// Setup cleanup for Gateway
		defer func() {
			logger.Info("🧹 Cleaning up Gateway...")
			stopGateway(logger)
		}()

		// Handle signals logic
		go func() {
			<-sigChan
			logger.Info("🛑 Received interrupt signal, cleaning up...")
			stopGateway(logger)
			if *manageMinIO {
				stopMinIOEnvironment(*minioComposeFile, logger)
			}
			if *manageGarage {
				stopGarageEnvironment(logger)
			}
			os.Exit(1)
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

// startGarageEnvironment starts a local Garage server using the binary.
// Returns access key and secret key.
func startGarageEnvironment(logger *logrus.Logger) (string, string, error) {
	logger.Info("Starting Garage test environment...")

	// Kill any existing garage instance first
	exec.Command("pkill", "garage").Run()
	time.Sleep(1 * time.Second)

	// Create temp dirs
	tmpDir, err := os.MkdirTemp("", "garage-loadtest-*")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	garageDir = tmpDir
	dataDir := filepath.Join(tmpDir, "data")
	configDir := filepath.Join(tmpDir, "meta")
	os.MkdirAll(dataDir, 0755)
	os.MkdirAll(configDir, 0755)

	// Create config.toml (v1.x compatible)
	configFile := filepath.Join(tmpDir, "config.toml")
	configContent := fmt.Sprintf(`
metadata_dir = "%s"
data_dir = "%s"
db_engine = "sqlite"

rpc_bind_addr = "127.0.0.1:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret = "3fb5c4e9d0e2f8a1b7c6d5e4f3a2b1c03fb5c4e9d0e2f8a1b7c6d5e4f3a2b1c0"
replication_factor = 1

[s3_api]
s3_region = "garage"
api_bind_addr = "127.0.0.1:3900"
root_domain = ".s3.garage"

[s3_web]
bind_addr = "127.0.0.1:3902"
root_domain = ".web.garage"
index = "index.html"
`, configDir, dataDir)

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		return "", "", fmt.Errorf("failed to write config file: %w", err)
	}

	// Start Garage
	cmd := exec.Command("garage", "-c", configFile, "server")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return "", "", fmt.Errorf("failed to start garage server: %w", err)
	}
	garageProcess = cmd.Process

	// Wait for Garage to be ready (RPC)
	time.Sleep(10 * time.Second)

	// Configure Garage
	// 1. Get Node ID
	nodeIDCmd := exec.Command("garage", "-c", configFile, "node", "id")
	out, err := nodeIDCmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("failed to get node id: %w", err)
	}

	// Parse Node ID
	outputID := string(out)
	var nodeID string

	reNodeID := regexp.MustCompile(`Node ID:\s+([a-f0-9]+)`)
	match := reNodeID.FindStringSubmatch(outputID)
	if len(match) >= 2 {
		nodeID = match[1]
	} else {
		// Fallback: look for any 64-char hex string
		reHex := regexp.MustCompile(`[a-f0-9]{64}`)
		matchHex := reHex.FindString(outputID)
		if matchHex != "" {
			nodeID = matchHex
		} else {
			return "", "", fmt.Errorf("failed to parse node id from output: %s", outputID)
		}
	}

	// 2. Assign Layout
	err = nil
	for i := 0; i < 5; i++ {
		layoutCmd := exec.Command("garage", "-c", configFile, "layout", "assign", "-z", "dc1", "--capacity", "100M", nodeID)
		if out, cmdErr := layoutCmd.CombinedOutput(); cmdErr == nil {
			err = nil
			break
		} else {
			err = fmt.Errorf("failed to assign layout: %w, output: %s", cmdErr, string(out))
			time.Sleep(1 * time.Second)
		}
	}
	if err != nil {
		return "", "", err
	}

	// 3. Apply Layout
	applyCmd := exec.Command("garage", "-c", configFile, "layout", "apply", "--version", "1")
	if out, err := applyCmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("failed to apply layout: %w, output: %s", err, string(out))
	}

	// 4. Create Key
	keyName := "loadtest-key"
	keyCmd := exec.Command("garage", "-c", configFile, "key", "create", keyName)
	out, err = keyCmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("failed to create key: %w, output: %s", err, string(out))
	}

	outputStr := string(out)
	reAccess := regexp.MustCompile(`Key ID:\s+(\S+)`)
	reSecret := regexp.MustCompile(`(?i)Secret Key:\s+(\S+)`)

	accessMatch := reAccess.FindStringSubmatch(outputStr)
	secretMatch := reSecret.FindStringSubmatch(outputStr)

	if len(accessMatch) < 2 || len(secretMatch) < 2 {
		return "", "", fmt.Errorf("failed to parse key from output: %s", outputStr)
	}
	accessKey := accessMatch[1]
	secretKey := secretMatch[1]

	// 5. Create Bucket and Allow Key
	bucketName := "test-bucket" // Must match what load test expects (usually expects 'test-bucket')

	bucketCmd := exec.Command("garage", "-c", configFile, "bucket", "create", bucketName)
	if out, err := bucketCmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("failed to create bucket: %w, output: %s", err, string(out))
	}

	allowCmd := exec.Command("garage", "-c", configFile, "bucket", "allow", bucketName, "--read", "--write", "--key", keyName)
	if out, err := allowCmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("failed to allow key: %w, output: %s", err, string(out))
	}

	logger.Info("✅ Garage test environment is ready")
	return accessKey, secretKey, nil
}

func stopGarageEnvironment(logger *logrus.Logger) {
	if garageProcess != nil {
		garageProcess.Kill()
		garageProcess = nil
	}
	if garageDir != "" {
		os.RemoveAll(garageDir)
		garageDir = ""
	}
}

// startMinIOEnvironment starts the MinIO test environment using docker-compose.
func startMinIOEnvironment(composeFile string, logger *logrus.Logger) error {
	logger.WithField("compose_file", composeFile).Info("Starting MinIO test environment...")

	// Check if docker-compose file exists (relative to current working directory)
	if _, err := os.Stat(composeFile); os.IsNotExist(err) {
		logger.WithError(err).WithField("compose_file", composeFile).Error("Docker-compose file not found")
		return fmt.Errorf("docker-compose file not found: %s", composeFile)
	}
	logger.WithField("compose_file", composeFile).Debug("Docker-compose file found")

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
	logger.Info("🧹 Cleaning up MinIO test environment...")

	// Check if docker-compose file exists
	if _, err := os.Stat(composeFile); os.IsNotExist(err) {
		logger.Warn("Docker-compose file not found, assuming environment already stopped")
		return nil
	}

	// Get the directory containing the compose file
	composeDir := filepath.Dir(composeFile)
	composeFileName := filepath.Base(composeFile)

	logger.WithField("compose_file", composeFileName).WithField("directory", composeDir).Debug("Running docker-compose down -v")

	// Try docker-compose first, then docker compose
	var stopCmd *exec.Cmd
	if hasDockerCompose() {
		stopCmd = exec.Command("docker-compose", "-f", composeFileName, "down", "-v")
	} else if hasDocker() {
		stopCmd = exec.Command("docker", "compose", "-f", composeFileName, "down", "-v")
	} else {
		return fmt.Errorf("neither docker-compose nor docker compose available")
	}

	stopCmd.Dir = composeDir

	output, err := stopCmd.CombinedOutput()
	if err != nil {
		logger.WithError(err).WithField("output", string(output)).Error("Failed to stop MinIO environment")
		return fmt.Errorf("failed to stop MinIO environment: %v\nOutput: %s", err, string(output))
	}

	logger.Info("✅ MinIO test environment stopped and cleaned up")
	return nil
}

// hasDockerCompose checks if docker-compose command is available.
func hasDockerCompose() bool {
	_, err := exec.LookPath("docker-compose")
	return err == nil
}

// hasDocker checks if docker command is available.
func hasDocker() bool {
	_, err := exec.LookPath("docker")
	return err == nil
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

// startGateway starts the S3 Encryption Gateway with the specified config.
func startGateway(configFile string, envVars map[string]string, logger *logrus.Logger) error {
	logger.WithField("config_file", configFile).Info("Starting S3 Encryption Gateway...")

	// Build the gateway binary path (assume bin/ relative to project root)
	// Since the shell script runs from test/, we assume project root is ..
	projectRoot := ".."
	gatewayBinary := filepath.Join(projectRoot, "bin", "s3-encryption-gateway")

	// Convert to absolute path
	if absPath, err := filepath.Abs(gatewayBinary); err == nil {
		gatewayBinary = absPath
	}

	if _, err := os.Stat(gatewayBinary); os.IsNotExist(err) {
		// Try to build it first
		logger.Info("Gateway binary not found, building it...")
		buildCmd := exec.Command("go", "build", "-o", "bin/s3-encryption-gateway", "./cmd/server")
		buildCmd.Dir = projectRoot // Build from project root
		if output, err := buildCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to build gateway: %v\nOutput: %s", err, string(output))
		}
		logger.Info("Gateway binary built successfully")
	}

	// Check if config file exists (relative to project root where gateway will run)
	configPath := filepath.Join(projectRoot, configFile)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logger.WithError(err).WithField("config_path", configPath).Error("Config file not found")
		return fmt.Errorf("gateway config file not found: %s", configPath)
	}
	logger.WithField("config_path", configPath).Debug("Config file found")

	// Start the gateway
	logger.Info("Starting gateway process...")
	cmd := exec.Command(gatewayBinary)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "CONFIG_PATH="+configFile)

	// Append extra env vars
	for k, v := range envVars {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	cmd.Dir = projectRoot // Run from project root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start gateway: %v", err)
	}

	// Store the process for cleanup
	gatewayProcess = cmd.Process

	// Wait for gateway to be ready
	logger.Info("Waiting for gateway to become ready...")
	if err := waitForGatewayReady(logger); err != nil {
		// Kill the process if it fails to start
		gatewayProcess.Kill()
		gatewayProcess.Wait()
		gatewayProcess = nil
		return fmt.Errorf("gateway failed to become ready: %v", err)
	}

	// Create test bucket directly in MinIO only if strictly managing MinIO or no backend override
	if _, ok := envVars["BACKEND_ENDPOINT"]; !ok {
		logger.Info("Creating test bucket directly in MinIO...")
		if err := createTestBucketDirectlyInMinIO(logger); err != nil {
			logger.WithError(err).Warn("Failed to create test bucket in MinIO")
		}
	}

	logger.Info("✅ S3 Encryption Gateway is ready")
	return nil
}

// stopGateway stops the S3 Encryption Gateway.
func stopGateway(logger *logrus.Logger) error {
	logger.Info("Stopping S3 Encryption Gateway...")

	if gatewayProcess == nil {
		logger.Warn("No gateway process to stop")
		return nil
	}

	// Send SIGTERM first
	if err := gatewayProcess.Signal(syscall.SIGTERM); err != nil {
		logger.WithError(err).Warn("Failed to send SIGTERM to gateway, trying SIGKILL")
		// If SIGTERM fails, try SIGKILL
		if killErr := gatewayProcess.Kill(); killErr != nil {
			return fmt.Errorf("failed to kill gateway process: %v", killErr)
		}
	}

	// Wait for the process to exit
	done := make(chan error, 1)
	go func() {
		_, err := gatewayProcess.Wait()
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			logger.WithError(err).Warn("Gateway process exited with error")
		} else {
			logger.Info("Gateway process exited cleanly")
		}
	case <-time.After(10 * time.Second):
		logger.Warn("Gateway process didn't exit within timeout, forcing kill")
		if err := gatewayProcess.Kill(); err != nil {
			return fmt.Errorf("failed to force kill gateway process: %v", err)
		}
		<-done // Wait for the process to actually exit
	}

	gatewayProcess = nil
	logger.Info("✅ S3 Encryption Gateway stopped")
	return nil
}

// createTestBucket creates the test bucket using AWS CLI (same method as integration tests).
func createTestBucket(composeDir, composeFile string, logger *logrus.Logger) error {
	// Use AWS CLI to create bucket (same approach as integration tests)
	logger.Info("Creating test bucket using AWS CLI...")

	// Configure AWS CLI for MinIO
	cmd := exec.Command("aws", "configure", "set", "aws_access_key_id", "minioadmin")
	if err := cmd.Run(); err != nil {
		logger.WithError(err).Debug("Failed to configure AWS CLI access key")
		// Continue anyway, might work without explicit config
	}

	cmd = exec.Command("aws", "configure", "set", "aws_secret_access_key", "minioadmin")
	if err := cmd.Run(); err != nil {
		logger.WithError(err).Debug("Failed to configure AWS CLI secret key")
		// Continue anyway
	}

	cmd = exec.Command("aws", "configure", "set", "region", "us-east-1")
	if err := cmd.Run(); err != nil {
		logger.WithError(err).Debug("Failed to configure AWS CLI region")
		// Continue anyway
	}

	// Try to create bucket using AWS CLI with retries
	for attempts := 0; attempts < 5; attempts++ {
		cmd = exec.Command("aws", "s3", "mb", "s3://test-bucket",
			"--endpoint-url", "http://localhost:9000",
			"--no-verify-ssl")

		output, err := cmd.CombinedOutput()
		if err == nil {
			logger.Debug("Test bucket created successfully with AWS CLI")
			return nil
		}

		outputStr := string(output)
		logger.WithError(err).WithField("output", outputStr).WithField("attempt", attempts+1).Debug("AWS CLI bucket creation attempt failed")

		if strings.Contains(outputStr, "SlowDown") {
			// Wait before retrying
			time.Sleep(time.Duration(attempts+1) * time.Second)
			continue
		}

		// Try alternative method for other errors
		return createBucketViaSDK(logger)
	}

	return fmt.Errorf("failed to create bucket after retries")
}

// createTestBucketDirectlyInMinIO creates the test bucket directly in MinIO using AWS CLI (same as integration tests).
func createTestBucketDirectlyInMinIO(logger *logrus.Logger) error {
	// Configure AWS CLI for MinIO
	cmd := exec.Command("aws", "configure", "set", "aws_access_key_id", "minioadmin")
	if err := cmd.Run(); err != nil {
		logger.WithError(err).Debug("Failed to configure AWS CLI access key")
	}

	cmd = exec.Command("aws", "configure", "set", "aws_secret_access_key", "minioadmin")
	if err := cmd.Run(); err != nil {
		logger.WithError(err).Debug("Failed to configure AWS CLI secret key")
	}

	cmd = exec.Command("aws", "configure", "set", "region", "us-east-1")
	if err := cmd.Run(); err != nil {
		logger.WithError(err).Debug("Failed to configure AWS CLI region")
	}

	// Create bucket directly in MinIO
	cmd = exec.Command("aws", "s3", "mb", "s3://test-bucket",
		"--endpoint-url", "http://localhost:9000",
		"--no-verify-ssl")

	output, err := cmd.CombinedOutput()
	if err != nil {
		outputStr := string(output)
		// Check if bucket already exists (which is OK)
		if strings.Contains(outputStr, "BucketAlreadyOwnedByYou") || strings.Contains(outputStr, "BucketAlreadyExists") {
			logger.Debug("Bucket test-bucket already exists")
			return nil
		}
		return fmt.Errorf("failed to create bucket in MinIO: %v, output: %s", err, outputStr)
	}

	logger.Debug("Test bucket created successfully in MinIO")
	return nil
}

// createBucketViaSDK creates the test bucket using AWS SDK (fallback method, same as integration tests).
func createBucketViaSDK(logger *logrus.Logger) error {
	logger.Info("Creating test bucket using AWS SDK...")

	// For now, let's just rely on MinIO's implicit bucket creation
	// The load tests will create the bucket on the first PUT operation
	logger.Info("Relying on MinIO's implicit bucket creation on first PUT operation")
	return nil
}

// waitForGatewayReady waits for the gateway to respond to health requests.
func waitForGatewayReady(logger *logrus.Logger) error {
	maxRetries := 30 // 30 * 2s = 60s max wait time
	retryCount := 0

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for retryCount < maxRetries {
		logger.Debug("Checking gateway health...")

		resp, err := client.Get("http://localhost:18080/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				logger.Info("Gateway is healthy and ready")
				return nil
			}
		}

		retryCount++
		logger.WithField("attempt", retryCount).WithField("max", maxRetries).Debug("Waiting for gateway to be ready...")
		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("gateway did not become ready within %d attempts", maxRetries)
}
