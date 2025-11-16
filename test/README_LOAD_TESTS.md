# Load Testing Suite for S3 Encryption Gateway

This document describes the comprehensive load testing suite designed to test and monitor the performance of range operations and multipart uploads in the S3 Encryption Gateway.

## Overview

The load testing suite provides:

- **Range Operations Testing**: Comprehensive testing of range requests including first-byte, last-byte, suffix, cross-chunk boundaries, and invalid ranges
- **Multipart Upload Testing**: Testing of multipart upload scenarios with configurable part sizes
- **Baseline Metrics Recording**: Automatic recording of performance baselines for regression tracking
- **Regression Analysis**: Automated detection of performance regressions with configurable thresholds
- **Prometheus Integration**: Optional integration with Prometheus for system-level metrics
- **Detailed Reporting**: Comprehensive metrics collection and reporting

## Quick Start

## MinIO Test Environment Integration

The load tests can automatically manage a MinIO test environment using Docker Compose:

```bash
# Run tests with automatic MinIO management
make test-load-minio

# Or use the shell script
cd test && ./run_load_tests.sh --manage-minio

# Run specific test types with MinIO
cd test && ./run_load_tests.sh --manage-minio --test-type range
```

The tests will:
1. Start MinIO using `docker-compose up -d`
2. Wait for MinIO to become healthy
3. Run the load tests against the MinIO instance
4. Stop and clean up MinIO environment after tests complete

### Running Range Load Tests

```go
config := RangeLoadTestConfig{
    GatewayURL:          "http://localhost:8080",
    NumWorkers:          10,
    Duration:            30 * time.Second,
    QPS:                 50,
    ObjectSize:          100 * 1024 * 1024, // 100MB objects
    ChunkSize:           64 * 1024,         // 64KB encryption chunks
    BaselineFile:        "baselines/range_test_baseline.json",
    RegressionThreshold: 10.0, // 10% regression threshold
}

results, err := RunRangeLoadTest(config, logger)
if err != nil {
    log.Fatal(err)
}

PrintLoadTestResults(results)
```

### Running Multipart Load Tests

```go
config := MultipartLoadTestConfig{
    GatewayURL:          "http://localhost:8080",
    NumWorkers:          5,
    Duration:            60 * time.Second,
    QPS:                 10,
    ObjectSize:          500 * 1024 * 1024, // 500MB objects
    PartSize:            100 * 1024 * 1024, // 100MB parts
    BaselineFile:        "baselines/multipart_test_baseline.json",
    RegressionThreshold: 15.0,
}

results, err := RunMultipartLoadTest(config, logger)
if err != nil {
    log.Fatal(err)
}

PrintLoadTestResults(results)
```

## Configuration Options

### RangeLoadTestConfig

| Field | Description | Default |
|-------|-------------|---------|
| `GatewayURL` | URL of the S3 Encryption Gateway | Required |
| `NumWorkers` | Number of concurrent worker goroutines | Required |
| `Duration` | How long to run the test | Required |
| `QPS` | Queries per second per worker | Required |
| `ObjectSize` | Size of test objects in bytes | Required |
| `ChunkSize` | Encryption chunk size (affects range behavior) | Required |
| `BaselineFile` | Path to save/load baseline metrics | Optional |
| `RegressionThreshold` | Max allowed regression percentage | 10.0 |

### MultipartLoadTestConfig

| Field | Description | Default |
|-------|-------------|---------|
| `GatewayURL` | URL of the S3 Encryption Gateway | Required |
| `NumWorkers` | Number of concurrent worker goroutines | Required |
| `Duration` | How long to run the test | Required |
| `QPS` | Queries per second per worker | Required |
| `ObjectSize` | Total size of multipart objects | Required |
| `PartSize` | Size of each upload part | Required |
| `BaselineFile` | Path to save/load baseline metrics | Optional |
| `RegressionThreshold` | Max allowed regression percentage | 10.0 |

## Command-Line Interface

### Basic Usage

```bash
# Build the load test binary
make build-loadtest

# Run basic load tests
./bin/loadtest

# Run range tests only
./bin/loadtest --test-type range

# Run with automatic MinIO management
./bin/loadtest --manage-minio

# Run with custom configuration and MinIO
./bin/loadtest --manage-minio --workers 20 --qps 100 --duration 120s

# Use custom docker-compose file
./bin/loadtest --manage-minio --minio-compose path/to/custom/docker-compose.yml

# Update baselines
./bin/loadtest --update-baseline --manage-minio
```

### Available Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--gateway-url` | S3 Encryption Gateway URL | `http://localhost:8080` |
| `--test-type` | Test type: range, multipart, or both | `both` |
| `--duration` | Test duration | `30s` |
| `--workers` | Number of worker goroutines | `5` |
| `--qps` | Queries per second per worker | `25` |
| `--object-size` | Object size in bytes | `52428800` (50MB) |
| `--chunk-size` | Encryption chunk size | `65536` (64KB) |
| `--part-size` | Multipart part size | `10485760` (10MB) |
| `--baseline-dir` | Directory for baseline files | `testdata/baselines` |
| `--threshold` | Regression threshold percentage | `10.0` |
| `--prometheus-url` | Prometheus URL for additional metrics | None |
| `--verbose` | Enable verbose logging | `false` |
| `--update-baseline` | Update baseline files | `false` |
| `--manage-minio` | Auto start/stop MinIO environment | `false` |
| `--minio-compose` | Path to MinIO docker-compose file | `test/docker-compose.yml` |

## Test Scenarios

### Range Request Scenarios

The range load test covers these scenarios:

- **First Byte Ranges**: `bytes=0-1023` - First 1KB of objects
- **Last Byte Ranges**: `bytes={size-1024}-{size-1}` - Last 1KB of objects
- **Suffix Ranges**: `bytes=-1024` - Last 1KB using suffix notation
- **Cross-Chunk Ranges**: Ranges that span encryption chunk boundaries
- **Large Ranges**: Large contiguous ranges for throughput testing
- **Invalid Ranges**: Out-of-bounds ranges to test error handling

### Multipart Upload Scenarios

The multipart load test supports:

- **Variable Object Sizes**: From small objects to large multi-part uploads
- **Configurable Part Sizes**: Control part size for different test scenarios
- **Concurrent Uploads**: Multiple workers uploading simultaneously
- **Error Simulation**: Testing error handling in multipart scenarios

## Metrics Collected

### General Metrics

- **Total Requests**: Total number of requests made
- **Successful Requests**: Number of successful requests
- **Failed Requests**: Number of failed requests
- **Error Rate**: Percentage of failed requests
- **Throughput**: Requests per second
- **Latency Statistics**: Min, Max, Average, P50, P95, P99 latencies
- **Data Transfer**: Total bytes sent and received

### Range-Specific Metrics

- **First Byte Ranges**: Count of first-byte range requests
- **Last Byte Ranges**: Count of last-byte range requests
- **Suffix Ranges**: Count of suffix range requests
- **Cross-Chunk Ranges**: Count of ranges crossing chunk boundaries
- **Invalid Ranges**: Count of invalid range requests
- **Time to First Byte**: Average and P95 time to first byte for range requests

### Multipart-Specific Metrics

- **Total Uploads**: Number of multipart uploads completed
- **Average Parts per Upload**: Average number of parts per upload
- **Average Part Size**: Average size of upload parts
- **Upload Time**: Average and P95 upload completion times
- **Failed Parts**: Number of failed part uploads

## Baseline Metrics and Regression Tracking

### Establishing Baselines

The first run of a load test with a `BaselineFile` specified will create the baseline:

```go
config := RangeLoadTestConfig{
    // ... other config ...
    BaselineFile: "baselines/range_baseline.json",
}

results, _ := RunRangeLoadTest(config, logger)
// First run creates baseline file
```

### Regression Analysis

Subsequent runs will automatically compare against the baseline:

```go
results, _ := RunRangeLoadTest(config, logger)

regression, err := AnalyzeRegression(results, config.BaselineFile, config.RegressionThreshold)
if err != nil {
    log.Printf("No baseline found: %v", err)
} else {
    PrintRegressionResult(regression)
}
```

### Regression Metrics

The system tracks regression in:

- **Latency**: Percentage change in average latency
- **Throughput**: Percentage change in requests per second
- **Error Rate**: Change in error rate (percentage points)

### Regression Thresholds

Configure acceptable regression thresholds:

```go
config := RangeLoadTestConfig{
    RegressionThreshold: 10.0, // Alert if any metric changes by >10%
}
```

## Prometheus Integration

For additional system-level metrics, integrate with Prometheus:

```go
// Run test
startTime := time.Now()
results, err := RunRangeLoadTest(config, logger)
endTime := time.Now()

// Query Prometheus for additional metrics
prometheusURL := "http://localhost:9090"
promMetrics, err := QueryPrometheusMetrics(prometheusURL, startTime, endTime)
if err != nil {
    log.Printf("Prometheus query failed: %v", err)
} else {
    // Metrics include: HTTP request durations, S3 operation durations,
    // encryption durations, memory usage, goroutine counts, etc.
    for metric, value := range promMetrics {
        fmt.Printf("%s: %v\n", metric, value)
    }
}
```

### Prometheus Metrics Collected

- `http_request_duration_seconds` (P95)
- `s3_operation_duration_seconds` (P95)
- `encryption_duration_seconds` (P95)
- `memory_alloc_bytes` (average)
- `goroutines` (average)

## Example Output

### Load Test Results

```
=== range_load_test Results ===
Timestamp: 2025-11-16T12:00:00Z
Duration: 30s
Total Requests: 1500
Successful: 1495
Failed: 5
Error Rate: 0.33%
Throughput: 50.00 req/s
Latency (avg): 45ms
Latency (p50): 42ms
Latency (p95): 67ms
Latency (p99): 89ms
Min Latency: 12ms
Max Latency: 156ms
Total Bytes Sent: 0
Total Bytes Received: 75GB

--- Range-Specific Metrics ---
First Byte Ranges: 300
Last Byte Ranges: 300
Suffix Ranges: 300
Cross-Chunk Ranges: 300
Invalid Ranges: 300
Time to First Byte (avg): 23ms
Time to First Byte (p95): 45ms

==============================
```

### Regression Analysis

```
=== Regression Analysis for range_load_test ===
Significant Regression: false
Latency Regression: 2.34%
Throughput Regression: -1.12%
Error Rate Regression: 0.15 percentage points

=====================================
```

## CI/CD Integration

### Automated Regression Testing

Integrate into your CI/CD pipeline:

```bash
#!/bin/bash

# Run range load test
go test -run TestRangeLoadTest ./test/

# Run multipart load test
go test -run TestMultipartLoadTest ./test/

# Check for significant regressions
if [ $? -ne 0 ]; then
    echo "Performance regression detected!"
    exit 1
fi
```

### Baseline Management

Store baselines in your repository for version control:

```
testdata/
  baselines/
    range_load_test_baseline.json
    multipart_load_test_baseline.json
```

### GitHub Actions Example

```yaml
name: Performance Tests
on: [push, pull_request]

jobs:
  load-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Load Tests
        run: |
          go test -run "TestRangeLoadTest|TestMultipartLoadTest" ./test/
      - name: Check Regressions
        run: |
          # Custom script to check regression results
          ./scripts/check_regressions.sh
```

## Best Practices

### Test Configuration

1. **Start Small**: Begin with small object sizes and low QPS to establish baselines
2. **Gradual Scaling**: Increase load gradually to find performance limits
3. **Realistic Scenarios**: Use object sizes and access patterns that match production
4. **Consistent Environment**: Run tests in consistent environments to ensure valid comparisons

### Baseline Management

1. **Version Baselines**: Store baselines per version or commit
2. **Regular Updates**: Update baselines when making intentional performance changes
3. **Environment Consistency**: Ensure baseline and current runs use identical configurations
4. **Documentation**: Document when and why baselines are updated

### Regression Alerts

1. **Threshold Tuning**: Set appropriate regression thresholds based on acceptable performance variance
2. **Multiple Metrics**: Monitor multiple metrics to avoid false positives
3. **Trend Analysis**: Consider trends over multiple runs rather than single point comparisons
4. **Root Cause Analysis**: Investigate regressions before updating baselines

## Troubleshooting

### Common Issues

1. **Gateway Connection Errors**: Ensure the gateway is running and accessible
2. **Baseline File Permissions**: Check write permissions for baseline file directory
3. **Prometheus Connection**: Verify Prometheus is running and accessible
4. **Memory Issues**: Large object sizes may cause memory issues; reduce for testing

### Debugging

Enable debug logging:

```go
logger := logrus.New()
logger.SetLevel(logrus.DebugLevel)

results, err := RunRangeLoadTest(config, logger)
```

### Performance Considerations

1. **Network Latency**: Account for network latency in threshold calculations
2. **System Resources**: Ensure adequate CPU/memory for load testing
3. **Concurrent Limits**: Don't overwhelm the gateway with too many workers
4. **Test Duration**: Longer tests provide more stable metrics but take more time

## Contributing

When adding new test scenarios:

1. Add the scenario to the appropriate test configuration
2. Update metrics collection if needed
3. Add documentation for the new scenario
4. Update baseline files after validation
5. Ensure tests pass consistently in CI/CD
