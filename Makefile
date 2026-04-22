.PHONY: build build-fips test test-fips test-conformance test-conformance-local test-conformance-minio test-conformance-external test-conformance-kms test-load test-load-range test-load-multipart test-load-soak test-load-minio test-load-garage test-load-prometheus test-load-baseline test-rotation test-fuzz test-comprehensive test-isolation-check lint clean run docker-build docker-push help

# Variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BINARY_NAME := s3-encryption-gateway
IMAGE_NAME ?= kenchrcum/s3-encryption-gateway
IMAGE_TAG ?= $(VERSION)

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@CGO_ENABLED=0 go build -ldflags="-w -s -X main.version=$(VERSION) -X main.commit=$(COMMIT)" \
		-o bin/$(BINARY_NAME)-$(VERSION) ./cmd/server

# Build FIPS-compliant binary
build-fips:
	@echo "Building FIPS-compliant $(BINARY_NAME)..."
	@GOFIPS140=v1.0.0 CGO_ENABLED=0 go build -tags=fips \
		-ldflags="-w -s -X main.version=$(VERSION) -X main.commit=$(COMMIT)" \
		-o bin/$(BINARY_NAME)-fips-$(VERSION) ./cmd/server

# Run tests
test:
	@echo "Running tests..."
	@go test -v -race -coverprofile=coverage.out ./...

# Run tests with FIPS build tag
test-fips:
	@echo "Running tests with FIPS build tag..."
	@GOFIPS140=v1.0.0 go test -v -race -tags=fips ./...

# ── Tier-2 conformance targets (require Docker via Testcontainers) ──────────
#
# test-conformance       All registered providers (local always, external when
#                        credentials are set).
# test-conformance-local Local providers only (MinIO + Garage); skips external.
# test-conformance-minio MinIO only — fastest signal, used as the PR gate.
# test-conformance-external External providers whose credential env vars are set;
#                            local providers skipped.

test-conformance:
	@echo "Running conformance tests (all registered providers)..."
	@go test -tags=conformance -race -v ./test/conformance/...

test-conformance-local:
	@echo "Running conformance tests (local providers only)..."
	@GATEWAY_TEST_SKIP_EXTERNAL=1 \
		go test -tags=conformance -race -v ./test/conformance/...

test-conformance-minio:
	@echo "Running conformance tests (MinIO only)..."
	@GATEWAY_TEST_SKIP_GARAGE=1 GATEWAY_TEST_SKIP_RUSTFS=1 GATEWAY_TEST_SKIP_EXTERNAL=1 \
		go test -tags=conformance -race -v ./test/conformance/...

test-conformance-external:
	@echo "Running conformance tests (external providers with credentials)..."
	@GATEWAY_TEST_SKIP_MINIO=1 GATEWAY_TEST_SKIP_GARAGE=1 GATEWAY_TEST_SKIP_RUSTFS=1 \
		go test -tags=conformance -race -v ./test/conformance/...

# KMS integration conformance test — starts a Cosmian KMS container alongside
# the S3 backend and exercises the full DEK wrap/unwrap path.
# Uses MinIO as the S3 backend (fastest signal); set GATEWAY_TEST_SKIP_COSMIAN=1
# to skip the KMS container if the image is unavailable.
test-conformance-kms:
	@echo "Running KMS integration conformance tests (MinIO + Cosmian KMS)..."
	@GATEWAY_TEST_SKIP_GARAGE=1 GATEWAY_TEST_SKIP_RUSTFS=1 GATEWAY_TEST_SKIP_EXTERNAL=1 \
		go test -tags=conformance -race -v \
		-run 'TestConformance/.*/KMS_' ./test/conformance/...

# Mechanical enforcement of the Docker-only deployment model.
test-isolation-check:
	@bash scripts/test-isolation.sh

# ── Tier-2 load tests (in-process, Docker via Testcontainers) ─────────────────
#
# All load targets run the same test functions in test/conformance/load_test.go
# using the in-process harness (MinIO via Testcontainers, no pre-running
# gateway or backend required).  Scale is controlled by environment variables:
#
#   SOAK_WORKERS     number of concurrent worker goroutines
#   SOAK_DURATION    test duration (e.g. "60s", "5m")
#   SOAK_QPS         requests per second per worker
#   SOAK_OBJECT_SIZE object size in bytes
#   SOAK_CHUNK_SIZE  encryption chunk size in bytes
#   SOAK_PART_SIZE   multipart part size in bytes (≥ 5242880)
#
# CI defaults (when env vars are unset): 3 workers · 5 s · 10 qps · 100 KiB
# Soak defaults:                        10 workers · 60 s · 25 qps · 50 MiB
#
# test-load            Fast CI gate: both load tests, small scale.
# test-load-range      Range-read concurrency only (CI scale).
# test-load-multipart  Multipart upload concurrency only (CI scale).
# test-load-soak       Full-scale soak: both tests, large objects, long run.
# test-load-minio      Soak: MinIO provider only (skip Garage).
# test-load-garage     Soak: Garage provider only (skip MinIO).

SOAK_ENV = \
	SOAK_WORKERS=10 \
	SOAK_DURATION=60s \
	SOAK_QPS=25 \
	SOAK_OBJECT_SIZE=52428800 \
	SOAK_PART_SIZE=10485760

test-load-range:
	@echo "Running range load tests (conformance suite, local providers, CI scale)..."
	@go test -tags=conformance -race -v -timeout 120s \
		-run 'TestConformance/.*/Load_RangeRead' ./test/conformance/...

test-load-multipart:
	@echo "Running multipart load tests (conformance suite, local providers, CI scale)..."
	@go test -tags=conformance -race -v -timeout 120s \
		-run 'TestConformance/.*/Load_Multipart' ./test/conformance/...

test-load: test-load-range test-load-multipart

# Full-scale soak: same tests, soak-scale parameters, no timeout limit.
test-load-soak:
	@echo "Running full-scale soak load tests (all local providers, 60 s, 10 workers, 50 MiB objects)..."
	@$(SOAK_ENV) go test -tags=conformance -v -timeout 0 \
		-run 'TestConformance/.*/Load_' ./test/conformance/...

# Soak MinIO only.
test-load-minio:
	@echo "Running full-scale soak load tests (MinIO only)..."
	@GATEWAY_TEST_SKIP_GARAGE=1 GATEWAY_TEST_SKIP_RUSTFS=1 GATEWAY_TEST_SKIP_EXTERNAL=1 \
		$(SOAK_ENV) go test -tags=conformance -v -timeout 0 \
		-run 'TestConformance/minio/Load_' ./test/conformance/...

# Soak Garage only.
test-load-garage:
	@echo "Running full-scale soak load tests (Garage only)..."
	@GATEWAY_TEST_SKIP_MINIO=1 GATEWAY_TEST_SKIP_RUSTFS=1 GATEWAY_TEST_SKIP_EXTERNAL=1 \
		$(SOAK_ENV) go test -tags=conformance -v -timeout 0 \
		-run 'TestConformance/garage/Load_' ./test/conformance/...

# Soak with custom duration override.
# Usage: make test-load-prometheus SOAK_DURATION=5m
test-load-prometheus:
	@echo "Running soak load tests (custom duration; set SOAK_DURATION to override)..."
	@$(SOAK_ENV) go test -tags=conformance -v -timeout 0 \
		-run 'TestConformance/.*/Load_' ./test/conformance/...

# Update baselines by running soak and capturing output.
# The soak tests log throughput/latency data; redirect to a file for tracking.
test-load-baseline:
	@echo "Running soak load tests for baseline capture..."
	@$(SOAK_ENV) go test -tags=conformance -v -timeout 0 \
		-run 'TestConformance/.*/Load_' ./test/conformance/... \
		2>&1 | tee testdata/baselines/soak_$(shell date +%Y%m%d_%H%M%S).log
	@echo "Baseline log written to testdata/baselines/"

# Run key rotation conformance tests (tier-2, all registered providers).
test-rotation:
	@echo "Running key rotation conformance tests (all registered providers)..."
	@go test -tags=conformance -race -v -run 'TestConformance/.*/Rotation_' ./test/conformance/...

# Run fuzz tests (as regression tests)
test-fuzz:
	@echo "Running fuzz tests (regression mode)..."
	@go test -v ./internal/crypto -run=Fuzz -fuzztime=1s

# Run comprehensive test suite.
# Requires only Docker (no docker-compose up, no pre-existing binaries).
test-comprehensive:
	@echo "Running comprehensive test suite..."
	@echo "1. Running tier-1 unit tests..."
	@go test -race -short ./...
	@echo "2. Running conformance tests (local providers via Testcontainers)..."
	@$(MAKE) test-conformance-local
	@echo "3. Checking test isolation (Docker-only model)..."
	@$(MAKE) test-isolation-check

# Run tests with coverage
test-coverage: test
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run linter
lint:
	@echo "Running linter..."
	@golangci-lint run ./...

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@goimports -w .

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html

# Run the server locally
run: build
	@echo "Running server..."
	@./bin/$(BINARY_NAME)

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	@docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		-t $(IMAGE_NAME):$(IMAGE_TAG) .

# Push Docker image
docker-push:
	@echo "Pushing Docker image..."
	@docker push $(IMAGE_NAME):$(IMAGE_TAG)

# Run all tests including integration
docker-all: docker-build docker-push

# Run security scan
security-scan:
	@echo "Running security scan..."
	@govulncheck ./...

# Install development tools
install-tools:
	@echo "Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install golang.org/x/tools/cmd/goimports@latest
	@go install golang.org/x/vuln/cmd/govulncheck@latest

# Generate test coverage report
coverage:
	@go test -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out

# Help target
help:
	@echo "Available targets:"
	@echo "  build              - Build the binary"
	@echo "  build-fips         - Build FIPS-compliant binary"
	@echo "  test               - Run tier-1 unit tests (-race)"
	@echo "  test-fips          - Run tests with FIPS build tag"
	@echo "  test-fuzz          - Run fuzz tests (regression mode)"
	@echo "  test-conformance   - Run tier-2 conformance tests (all providers; requires Docker)"
	@echo "  test-conformance-local  - Conformance: local providers (MinIO + Garage)"
	@echo "  test-conformance-minio  - Conformance: MinIO only (PR gate)"
	@echo "  test-conformance-external - Conformance: external providers with credentials"
	@echo "  test-conformance-kms     - Conformance: KMS envelope encryption (MinIO + Cosmian KMS)"
	@echo "  test-isolation-check    - Check test/ does not reference docker-compose / hard-coded ports"
	@echo "  test-load          - CI load gate: range + multipart, small scale (5 s, 100 KiB)"
	@echo "  test-load-range    - CI load gate: range-read concurrency only"
	@echo "  test-load-multipart- CI load gate: multipart upload concurrency only"
	@echo "  test-load-soak     - Full soak: both tests, 60 s, 10 workers, 50 MiB objects"
	@echo "  test-load-minio    - Full soak: MinIO provider only"
	@echo "  test-load-garage   - Full soak: Garage provider only"
	@echo "  test-load-baseline - Soak run with log capture to testdata/baselines/"
	@echo "  test-load-prometheus-Soak run with custom duration (set SOAK_DURATION)"
	@echo "  test-rotation      - Run key rotation conformance tests (tier-2, all providers)"
	@echo "  test-comprehensive - Run comprehensive test suite (tier-1 + local conformance + isolation check)"
	@echo "  test-coverage      - Run tests with HTML coverage report"
	@echo "  lint               - Run linter"
	@echo "  fmt                - Format code"
	@echo "  clean              - Clean build artifacts"
	@echo "  run                - Build and run the server"
	@echo "  docker-build       - Build Docker image"
	@echo "  docker-push        - Push Docker image"
	@echo "  security-scan      - Run security vulnerability scan"
	@echo "  install-tools      - Install development tools"
	@echo "  coverage           - Generate test coverage report"
	@echo "  help               - Show this help message"
