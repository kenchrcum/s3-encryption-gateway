#!/bin/bash

# Load Test Runner Script for S3 Encryption Gateway
# This script provides an easy way to run load tests with various configurations

set -e

# Default values
GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
TEST_TYPE="${TEST_TYPE:-both}"
DURATION="${DURATION:-30s}"
WORKERS="${WORKERS:-5}"
QPS="${QPS:-25}"
OBJECT_SIZE="${OBJECT_SIZE:-$((50*1024*1024))}"  # 50MB default
CHUNK_SIZE="${CHUNK_SIZE:-$((64*1024))}"        # 64KB default
PART_SIZE="${PART_SIZE:-$((10*1024*1024))}"     # 10MB default
BASELINE_DIR="${BASELINE_DIR:-testdata/baselines}"
THRESHOLD="${THRESHOLD:-10.0}"
PROMETHEUS_URL="${PROMETHEUS_URL:-}"
VERBOSE="${VERBOSE:-false}"
UPDATE_BASELINE="${UPDATE_BASELINE:-false}"
MANAGE_MINIO="${MANAGE_MINIO:-false}"
MINIO_COMPOSE="${MINIO_COMPOSE:-docker-compose.yml}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
S3 Encryption Gateway Load Test Runner

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -h, --help                  Show this help message
    -u, --gateway-url URL       Gateway URL (default: $GATEWAY_URL)
    -t, --test-type TYPE        Test type: range, multipart, or both (default: $TEST_TYPE)
    -d, --duration DURATION     Test duration (default: $DURATION)
    -w, --workers NUM           Number of worker goroutines (default: $WORKERS)
    -q, --qps NUM               Queries per second per worker (default: $QPS)
    -s, --object-size SIZE      Object size in bytes (default: $OBJECT_SIZE)
    -c, --chunk-size SIZE       Encryption chunk size (default: $CHUNK_SIZE)
    -p, --part-size SIZE        Multipart part size (default: $PART_SIZE)
    -b, --baseline-dir DIR      Baseline directory (default: $BASELINE_DIR)
    --threshold PERCENT         Regression threshold (default: $THRESHOLD)
    --prometheus URL            Prometheus URL for metrics
    -v, --verbose               Enable verbose logging
    --update-baseline           Update baseline files instead of checking regression
    --manage-minio              Automatically start/stop MinIO test environment
    --minio-compose FILE        Path to MinIO docker-compose file (default: test/docker-compose.yml)

ENVIRONMENT VARIABLES:
    GATEWAY_URL                 Gateway URL
    TEST_TYPE                   Test type
    DURATION                    Test duration
    WORKERS                     Number of workers
    QPS                         Queries per second per worker
    OBJECT_SIZE                 Object size in bytes
    CHUNK_SIZE                  Encryption chunk size
    PART_SIZE                   Multipart part size
    BASELINE_DIR                Baseline directory
    THRESHOLD                   Regression threshold
    PROMETHEUS_URL              Prometheus URL
    VERBOSE                     Enable verbose logging
    UPDATE_BASELINE             Update baseline files
    MANAGE_MINIO                Automatically manage MinIO environment
    MINIO_COMPOSE               Path to MinIO docker-compose file

EXAMPLES:
    # Run basic load tests
    $0

    # Run range tests only with custom settings
    $0 --test-type range --workers 10 --qps 50 --duration 60s

    # Run multipart tests with large objects
    $0 --test-type multipart --object-size \$((500*1024*1024)) --part-size \$((100*1024*1024))

    # Update baselines for CI/CD
    $0 --update-baseline

    # Run with Prometheus metrics
    $0 --prometheus http://localhost:9090

    # Run verbose tests for debugging
    $0 --verbose

    # Run tests with automatic MinIO management
    $0 --manage-minio

    # Run tests with custom MinIO compose file
    $0 --manage-minio --minio-compose path/to/custom/docker-compose.yml
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -u|--gateway-url)
            GATEWAY_URL="$2"
            shift 2
            ;;
        -t|--test-type)
            TEST_TYPE="$2"
            shift 2
            ;;
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -w|--workers)
            WORKERS="$2"
            shift 2
            ;;
        -q|--qps)
            QPS="$2"
            shift 2
            ;;
        -s|--object-size)
            OBJECT_SIZE="$2"
            shift 2
            ;;
        -c|--chunk-size)
            CHUNK_SIZE="$2"
            shift 2
            ;;
        -p|--part-size)
            PART_SIZE="$2"
            shift 2
            ;;
        -b|--baseline-dir)
            BASELINE_DIR="$2"
            shift 2
            ;;
        --threshold)
            THRESHOLD="$2"
            shift 2
            ;;
        --prometheus)
            PROMETHEUS_URL="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --update-baseline)
            UPDATE_BASELINE=true
            shift
            ;;
        --manage-minio)
            MANAGE_MINIO=true
            shift
            ;;
        --minio-compose)
            MINIO_COMPOSE="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            log_info "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Validate inputs
case $TEST_TYPE in
    range|multipart|both) ;;
    *)
        log_error "Invalid test type: $TEST_TYPE. Must be range, multipart, or both"
        exit 1
        ;;
esac

# Build command arguments
ARGS=(
    "--gateway-url" "$GATEWAY_URL"
    "--test-type" "$TEST_TYPE"
    "--duration" "$DURATION"
    "--workers" "$WORKERS"
    "--qps" "$QPS"
    "--object-size" "$OBJECT_SIZE"
    "--chunk-size" "$CHUNK_SIZE"
    "--part-size" "$PART_SIZE"
    "--baseline-dir" "$BASELINE_DIR"
    "--threshold" "$THRESHOLD"
)

if [[ -n "$PROMETHEUS_URL" ]]; then
    ARGS+=("--prometheus-url" "$PROMETHEUS_URL")
fi

if [[ "$VERBOSE" == "true" ]]; then
    ARGS+=("--verbose")
fi

if [[ "$UPDATE_BASELINE" == "true" ]]; then
    ARGS+=("--update-baseline")
fi

if [[ "$MANAGE_MINIO" == "true" ]]; then
    ARGS+=("--manage-minio")
fi

ARGS+=("--minio-compose" "$MINIO_COMPOSE")

# Print configuration
log_info "Starting load tests with configuration:"
echo "  Gateway URL: $GATEWAY_URL"
echo "  Test Type: $TEST_TYPE"
echo "  Duration: $DURATION"
echo "  Workers: $WORKERS"
echo "  QPS per Worker: $QPS"
echo "  Object Size: $OBJECT_SIZE bytes ($((OBJECT_SIZE/1024/1024))MB)"
echo "  Chunk Size: $CHUNK_SIZE bytes ($((CHUNK_SIZE/1024))KB)"
echo "  Part Size: $PART_SIZE bytes ($((PART_SIZE/1024/1024))MB)"
echo "  Baseline Dir: $BASELINE_DIR"
echo "  Threshold: ${THRESHOLD}%"
if [[ -n "$PROMETHEUS_URL" ]]; then
    echo "  Prometheus URL: $PROMETHEUS_URL"
fi
echo "  Verbose: $VERBOSE"
echo "  Update Baseline: $UPDATE_BASELINE"
echo "  Manage MinIO: $MANAGE_MINIO"
echo "  MinIO Compose: $MINIO_COMPOSE"
echo

# Check if gateway is accessible
log_info "Checking gateway connectivity..."
if ! curl -f -s "$GATEWAY_URL/health" > /dev/null 2>&1; then
    # Try alternative health check endpoint
    if ! curl -f -s "$GATEWAY_URL/" > /dev/null 2>&1; then
        log_warn "Gateway at $GATEWAY_URL may not be accessible"
        log_warn "Make sure the gateway is running and accessible"
    fi
fi

# Run the load tests
log_info "Running load tests..."
if go run ../cmd/loadtest/main.go "${ARGS[@]}"; then
    log_success "Load tests completed successfully"
    exit 0
else
    log_error "Load tests failed"
    exit 1
fi
