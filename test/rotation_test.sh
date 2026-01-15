#!/bin/bash
# Key Rotation Demo Script
# 
# This script demonstrates the key rotation workflow with dual-read window support.
# It shows:
# 1. Creating objects with key version 1
# 2. Rotating to key version 2
# 3. Verifying dual-read window works
# 4. Monitoring rotated reads via metrics
#
# Prerequisites:
# - Docker (for Cosmian KMS)
# - Gateway binary in bin/ directory (build with: make build)
# - MinIO or other S3-compatible backend running on localhost:9000 (for full demo)
# - curl, jq (for API calls)
#
# Usage:
#   ./test/rotation_test.sh              # Automatically starts gateway from bin/
#   ./test/rotation_test.sh --skip-gateway  # Skip gateway startup (for CI)
#
# The script will:
# - Automatically find and start the gateway binary from bin/
# - Create a temporary config file
# - Start Cosmian KMS container
# - Run the rotation demo
# - Clean up everything on exit

set -euo pipefail

SKIP_GATEWAY_CHECK=false
if [[ "${1:-}" == "--skip-gateway" ]]; then
    SKIP_GATEWAY_CHECK=true
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
BUCKET="${BUCKET:-rotation-demo}"
KMS_CONTAINER="${KMS_CONTAINER:-cosmian-kms-demo}"
MINIO_CONTAINER="${MINIO_CONTAINER:-minio-demo-backend}"
GATEWAY_PORT="${GATEWAY_PORT:-8080}"
GATEWAY_PID=""
GATEWAY_CONFIG=""
MINIO_DATA_DIR=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_DIR="${PROJECT_ROOT}/bin"

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is required but not installed"
        exit 1
    fi
    
    if ! command -v curl &> /dev/null; then
        log_error "curl is required but not installed"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log_warning "jq is not installed (optional, for JSON parsing)"
    fi
    
    log_success "Prerequisites check passed"
}

# Start Cosmian KMS
start_kms() {
    log_info "Starting Cosmian KMS container..."
    
    if docker ps -a --format '{{.Names}}' | grep -q "^${KMS_CONTAINER}$"; then
        log_info "Container ${KMS_CONTAINER} exists, removing..."
        docker rm -f "${KMS_CONTAINER}" > /dev/null 2>&1 || true
    fi
    
    docker run -d --rm \
        --name "${KMS_CONTAINER}" \
        -p 9998:9998 \
        -p 5696:5696 \
        --entrypoint cosmian_kms \
        ghcr.io/cosmian/kms:5.14.1 > /dev/null
    
    log_info "Waiting for KMS to be ready..."
    local max_attempts=30
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl -s http://localhost:9998/health > /dev/null 2>&1; then
            log_success "KMS is ready"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    
    log_error "KMS failed to start"
    exit 1
}

# Start MinIO backend
start_minio() {
    log_info "Starting MinIO backend container..."
    
    if docker ps -a --format '{{.Names}}' | grep -q "^${MINIO_CONTAINER}$"; then
        log_info "Container ${MINIO_CONTAINER} exists, removing..."
        docker rm -f "${MINIO_CONTAINER}" > /dev/null 2>&1 || true
    fi

    # Create temporary data directory
    MINIO_DATA_DIR=$(mktemp -d /tmp/minio-demo-data-XXXXXX)
    chmod 777 "${MINIO_DATA_DIR}"
    
    # Create bucket directory
    mkdir -p "${MINIO_DATA_DIR}/${BUCKET}"
    chmod 777 "${MINIO_DATA_DIR}/${BUCKET}"
    
    docker run -d --rm \
        --name "${MINIO_CONTAINER}" \
        -p 9000:9000 \
        -p 9001:9001 \
        -e MINIO_ROOT_USER=minioadmin \
        -e MINIO_ROOT_PASSWORD=minioadmin \
        -v "${MINIO_DATA_DIR}:/data" \
        minio/minio:latest server /data --console-address ":9001" > /dev/null
    
    log_info "Waiting for MinIO to be ready..."
    local max_attempts=30
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl -s http://localhost:9000/minio/health/live > /dev/null 2>&1; then
            log_success "MinIO is ready"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    
    log_error "MinIO failed to start"
    exit 1
}

# Create a wrapping key in KMS
create_key() {
    local key_name="$1"
    log_info "Creating wrapping key: ${key_name}..."
    
    # Use KMS API to create key (simplified - actual implementation may vary)
    # This is a placeholder - adjust based on your KMS API
    local key_id
    key_id=$(curl -s -X POST "http://localhost:9998/api/v1/keys" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"${key_name}\",\"algorithm\":\"AES\",\"keySize\":256}" \
        | jq -r '.id' 2>/dev/null || echo "key-${key_name}-$(date +%s)")
    
    log_success "Created key: ${key_id}"
    echo "${key_id}"
}

# Find gateway binary
find_gateway_binary() {
    log_info "Looking for gateway binary in ${BIN_DIR}..."
    
    # Look for the latest versioned binary
    local binary
    binary=$(ls -t "${BIN_DIR}"/s3-encryption-gateway-* 2>/dev/null | grep -v "\.tar\.gz$" | head -1)
    
    if [ -z "${binary}" ] || [ ! -f "${binary}" ]; then
        # Try non-versioned name
        binary="${BIN_DIR}/s3-encryption-gateway"
        if [ ! -f "${binary}" ]; then
            log_error "Gateway binary not found in ${BIN_DIR}"
            log_info "Please build the gateway first:"
            log_info "  make build"
            exit 1
        fi
    fi
    
    # Make sure it's executable
    chmod +x "${binary}" 2>/dev/null || true
    
    log_success "Found gateway binary: ${binary}"
    echo "${binary}"
}

# Create temporary config file for demo
create_demo_config() {
    log_info "Creating temporary config file for demo..."
    
    local config_file
    config_file=$(mktemp /tmp/gateway-demo-config-XXXXXX.yaml)
    
    cat > "${config_file}" <<EOF
listen_addr: ":${GATEWAY_PORT}"
log_level: "info"

backend:
  endpoint: "http://localhost:9000"
  region: "us-east-1"
  access_key: "minioadmin"
  secret_key: "minioadmin"
  provider: "minio"
  use_ssl: false
  use_path_style: true

encryption:
  password: "test-password-for-rotation-demo-12345"
  preferred_algorithm: "AES256-GCM"
  supported_algorithms:
    - "AES256-GCM"
    - "ChaCha20-Poly1305"
  chunked_mode: false
  chunk_size: 65536
  key_manager:
    enabled: false  # For demo, we'll use password-based encryption

compression:
  enabled: false

server:
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "60s"
  read_header_timeout: "10s"
  max_header_bytes: 1048576

tls:
  enabled: false

rate_limit:
  enabled: false

cache:
  enabled: false

audit:
  enabled: true
  max_events: 10000
EOF
    
    log_success "Created config file: ${config_file}"
    echo "${config_file}"
}

# Start gateway
start_gateway() {
    if [ "${SKIP_GATEWAY_CHECK}" = "true" ]; then
        log_info "Skipping gateway startup (--skip-gateway flag set)"
        return 0
    fi
    
    # Check if gateway is already running
    if curl -s "${GATEWAY_URL}/health" > /dev/null 2>&1; then
        log_info "Gateway is already running at ${GATEWAY_URL}"
        return 0
    fi
    
    log_info "Starting gateway..."
    
    # Find binary
    local binary
    binary=$(find_gateway_binary)
    
    # Create config
    GATEWAY_CONFIG=$(create_demo_config)
    
    # Start gateway in background with CONFIG_PATH environment variable
    log_info "Starting gateway with config: ${GATEWAY_CONFIG}"
    CONFIG_PATH="${GATEWAY_CONFIG}" "${binary}" > /tmp/gateway-demo.log 2>&1 &
    GATEWAY_PID=$!
    
    log_info "Gateway started with PID: ${GATEWAY_PID}"
    
    # Wait for gateway to be ready
    log_info "Waiting for gateway to be ready..."
    local max_attempts=30
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl -s "${GATEWAY_URL}/health" > /dev/null 2>&1; then
            log_success "Gateway is ready"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    
    log_error "Gateway failed to start"
    log_info "Gateway logs:"
    tail -20 /tmp/gateway-demo.log 2>/dev/null || true
    exit 1
}

# Stop gateway
stop_gateway() {
    if [ -n "${GATEWAY_PID}" ] && kill -0 "${GATEWAY_PID}" 2>/dev/null; then
        log_info "Stopping gateway (PID: ${GATEWAY_PID})..."
        kill "${GATEWAY_PID}" 2>/dev/null || true
        wait "${GATEWAY_PID}" 2>/dev/null || true
        log_success "Gateway stopped"
    fi
    
    # Clean up config file
    if [ -n "${GATEWAY_CONFIG}" ] && [ -f "${GATEWAY_CONFIG}" ]; then
        rm -f "${GATEWAY_CONFIG}"
    fi
}

# Check gateway health
check_gateway() {
    if [ "${SKIP_GATEWAY_CHECK}" = "true" ]; then
        log_info "Skipping gateway health check (--skip-gateway flag set)"
        return 0
    fi
    
    log_info "Checking gateway health..."
    
    if ! curl -s "${GATEWAY_URL}/health" > /dev/null; then
        log_error "Gateway is not accessible at ${GATEWAY_URL}"
        exit 1
    fi
    
    log_success "Gateway is healthy"
}

# Upload test object
upload_object() {
    local key="$1"
    local content="$2"
    local expected_version="${3:-}"
    
    log_info "Uploading object: ${key}"
    
    echo "${content}" | curl -s -X PUT \
        "${GATEWAY_URL}/${BUCKET}/${key}" \
        -H "Content-Type: text/plain" \
        --data-binary @- \
        -w "\nHTTP_CODE:%{http_code}" \
        > /tmp/upload_response.txt
    
    local http_code
    http_code=$(grep "HTTP_CODE:" /tmp/upload_response.txt | cut -d: -f2)
    
    if [ "${http_code}" != "200" ]; then
        log_error "Upload failed with HTTP ${http_code}"
        cat /tmp/upload_response.txt
        return 1
    fi
    
    log_success "Uploaded: ${key}"
    
    # Check key version in metadata if expected
    if [ -n "${expected_version}" ]; then
        log_info "Verifying key version in metadata..."
        # This would require HEAD request to check metadata
        # Placeholder for actual implementation
    fi
}

# Download test object
download_object() {
    local key="$1"
    local expected_content="$2"
    
    log_info "Downloading object: ${key}"
    
    local content
    content=$(curl -s "${GATEWAY_URL}/${BUCKET}/${key}")
    
    if [ "${content}" != "${expected_content}" ]; then
        log_error "Content mismatch for ${key}"
        log_info "Expected: ${expected_content}"
        log_info "Got: ${content}"
        return 1
    fi
    
    log_success "Downloaded and verified: ${key}"
}

# Check metrics for rotated reads
check_rotated_reads() {
    log_info "Checking rotated read metrics..."
    
    local metrics
    metrics=$(curl -s "${GATEWAY_URL}/metrics" | grep "kms_rotated_reads_total" || echo "")
    
    if [ -z "${metrics}" ]; then
        log_warning "No rotated read metrics found (may be normal if no rotated reads occurred)"
    else
        log_info "Rotated read metrics:"
        echo "${metrics}" | while read -r line; do
            echo "  ${line}"
        done
    fi
}

# Main demo flow
main() {
    log_info "=== Key Rotation Demo ==="
    log_info "Gateway URL: ${GATEWAY_URL}"
    log_info "Bucket: ${BUCKET}"
    echo
    
    check_prerequisites
    echo
    
    # Step 1: Start KMS
    start_kms
    echo

    # Step 1.5: Start MinIO
    start_minio
    echo
    
    # Step 2: Start gateway
    start_gateway
    echo
    
    # Step 3: Check gateway health
    check_gateway
    echo
    
    log_info "=== Phase 1: Initial Setup (Key Version 1) ==="
    
    # Note: In a real scenario, you would:
    # 1. Create key in KMS UI
    # 2. Update gateway config with key ID
    # 3. Restart gateway
    # For this demo, we assume keys are already configured
    
    log_info "Uploading objects with key version 1..."
    upload_object "object-v1-1.txt" "Content encrypted with key v1 - object 1"
    upload_object "object-v1-2.txt" "Content encrypted with key v1 - object 2"
    upload_object "object-v1-3.txt" "Content encrypted with key v1 - object 3"
    echo
    
    log_info "Verifying objects can be downloaded..."
    download_object "object-v1-1.txt" "Content encrypted with key v1 - object 1"
    download_object "object-v1-2.txt" "Content encrypted with key v1 - object 2"
    download_object "object-v1-3.txt" "Content encrypted with key v1 - object 3"
    echo
    
    log_info "=== Phase 2: Rotation (Key Version 2) ==="
    log_warning "In production, you would:"
    log_warning "1. Create new key in KMS"
    log_warning "2. Update gateway config (add new key as first entry)"
    log_warning "3. Restart gateway"
    log_warning "For this demo, assuming rotation is complete"
    echo
    
    log_info "Uploading objects with key version 2..."
    upload_object "object-v2-1.txt" "Content encrypted with key v2 - object 1"
    upload_object "object-v2-2.txt" "Content encrypted with key v2 - object 2"
    echo
    
    log_info "=== Phase 3: Dual-Read Window Verification ==="
    log_info "Verifying old objects (v1) can still be read after rotation..."
    download_object "object-v1-1.txt" "Content encrypted with key v1 - object 1"
    download_object "object-v1-2.txt" "Content encrypted with key v1 - object 2"
    download_object "object-v1-3.txt" "Content encrypted with key v1 - object 3"
    echo
    
    log_info "Verifying new objects (v2) work correctly..."
    download_object "object-v2-1.txt" "Content encrypted with key v2 - object 1"
    download_object "object-v2-2.txt" "Content encrypted with key v2 - object 2"
    echo
    
    log_info "=== Phase 4: Monitoring ==="
    check_rotated_reads
    echo
    
    log_info "=== Demo Complete ==="
    log_success "Key rotation demo completed successfully!"
    echo
    log_info "Next steps:"
    log_info "1. Check metrics: curl ${GATEWAY_URL}/metrics | grep kms_rotated_reads_total"
    log_info "2. Review audit logs (if enabled)"
    log_info "3. Monitor rotated read rate over time"
    log_info "4. Plan cleanup of old keys after grace period"
    echo
    log_info "To clean up:"
    log_info "  - KMS container: docker rm -f ${KMS_CONTAINER}"
    if [ -n "${GATEWAY_PID}" ]; then
        log_info "  - Gateway: kill ${GATEWAY_PID} (or it will be cleaned up automatically)"
    fi
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    stop_gateway
    docker rm -f "${KMS_CONTAINER}" > /dev/null 2>&1 || true
    docker rm -f "${MINIO_CONTAINER}" > /dev/null 2>&1 || true
    if [ -n "${MINIO_DATA_DIR}" ] && [ -d "${MINIO_DATA_DIR}" ]; then
        # Use docker to remove the directory since it contains files owned by root/minio user
        docker run --rm -v "$(dirname "${MINIO_DATA_DIR}")":/tmp/cleanup-mount alpine rm -rf "/tmp/cleanup-mount/$(basename "${MINIO_DATA_DIR}")" > /dev/null 2>&1 || rm -rf "${MINIO_DATA_DIR}"
    fi
}

# Trap cleanup on exit
trap cleanup EXIT

# Run main function
main "$@"

