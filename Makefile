.PHONY: build build-fips test test-fips test-conformance test-conformance-local test-conformance-minio test-conformance-external test-soak test-load test-load-range test-load-multipart test-load-soak test-load-minio test-load-garage test-load-prometheus test-load-baseline test-load-external test-chaos test-comprehensive test-isolation-check lint clean run docker-build docker-push help

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

# Mechanical enforcement of the Docker-only deployment model.
test-isolation-check:
	@bash scripts/test-isolation.sh

# ── Legacy/deprecated targets (kept for one minor version) ───────────────────
# Run integration tests (requires Docker) — DEPRECATED; use test-conformance-minio
test-integration:
	@echo "[DEPRECATED] Use 'make test-conformance-minio' instead."
	@go test -v -tags=integration ./test/... -run TestS3Gateway

# ── Tier-2 load tests (in-process, Docker via Testcontainers) ─────────────────
#
# Load tests live in the conformance suite (test/conformance/load_test.go) and
# run fully in-process — no pre-running gateway or backend required.
#
# test-load        All load tests (range + multipart) against local providers.
# test-load-range  Range-read concurrency only.
# test-load-multipart  Multipart upload concurrency only.
# test-load-soak   Long-running soak using the external binary (cmd/loadtest).
#                  Requires a gateway + backend already running.  Pass
#                  GATEWAY_URL=http://host:port to override the default.
#
# The old shell-script driver (test/run_load_tests.sh) and binary
# (cmd/loadtest) are retained for manual/external soak runs and CI
# environments that pre-provision a gateway.

test-load-range:
	@echo "Running range load tests (conformance suite, local providers)..."
	@go test -tags=conformance -race -v -run 'TestConformance/.*/Load_RangeRead' ./test/conformance/...

test-load-multipart:
	@echo "Running multipart load tests (conformance suite, local providers)..."
	@go test -tags=conformance -race -v -run 'TestConformance/.*/Load_Multipart' ./test/conformance/...

test-load: test-load-range test-load-multipart

# Long-running soak (external binary, requires a running gateway + backend).
# Usage: make test-load-soak GATEWAY_URL=http://localhost:8080
test-load-soak:
	@echo "Running soak load tests (external binary, requires running gateway)..."
	@echo "Gateway URL: $${GATEWAY_URL:-http://localhost:8080}"
	@go run ./cmd/loadtest \
		--gateway-url "$${GATEWAY_URL:-http://localhost:8080}" \
		--test-type both \
		--duration 60s \
		--workers 10 \
		--qps 50

# Soak with automatic MinIO + gateway management (unchanged from legacy).
test-load-minio:
	@echo "Running soak load tests with automatic MinIO and Gateway management..."
	@echo "Environment will be removed even if tests are interrupted."
	@cd test && ./run_load_tests.sh --manage-minio

# Soak with automatic Garage + gateway management (unchanged from legacy).
test-load-garage:
	@echo "Running soak load tests with automatic Garage and Gateway management..."
	@echo "Environment will be removed even if tests are interrupted."
	@cd test && ./run_load_tests.sh --manage-garage

# Soak: run with Prometheus metrics (requires running Prometheus).
test-load-prometheus:
	@echo "Running soak load tests with Prometheus metrics..."
	@cd test && ./run_load_tests.sh --prometheus http://localhost:9090

# Soak: update regression baselines.
test-load-baseline:
	@echo "Running soak load tests and updating baselines..."
	@cd test && ./run_load_tests.sh --update-baseline

# Run key rotation conformance tests.
# Rotation tests live in the tier-2 conformance suite (test/conformance/rotation_test.go)
# and run against every registered provider.  The old shell-script demo
# (test/rotation_test.sh) is retained as documentation but is no longer
# part of the automated test pipeline.
test-rotation:
	@echo "Running key rotation conformance tests (all registered providers)..."
	@go test -tags=conformance -race -v -run 'TestConformance/.*/Rotation_' ./test/conformance/...

# Run fuzz tests (as regression tests)
test-fuzz:
	@echo "Running fuzz tests (regression mode)..."
	@go test -v ./internal/crypto -run=Fuzz -fuzztime=1s

# Build load test binary
build-loadtest:
	@echo "Building load test binary..."
	@go build -o bin/loadtest ./cmd/loadtest

# Run all tests including integration
test-all: test test-integration

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

# DEPRECATED targets — kept as aliases for one minor version.
test-comprehensive-legacy:
	@echo "[DEPRECATED] Use 'make test-comprehensive' instead."
	@echo "1. Running code tests..."
	@go test ./internal/* -v &> comprehensive_step_1.log
	@echo "2. Running fuzz tests (regression mode)..."
	@$(MAKE) test-fuzz &> comprehensive_step_2.log
	@echo "3. Running integration tests..."
	@go test -v ./test &> comprehensive_step_3.log

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
	@echo "  test-isolation-check    - Check test/ does not reference docker-compose / hard-coded ports"
	@echo "  test-integration   - [DEPRECATED] Use test-conformance-minio"
	@echo "  test-load          - Run all load tests (tier-2, local providers; range + multipart)"
	@echo "  test-load-range    - Load: range-read concurrency (tier-2, local providers)"
	@echo "  test-load-multipart- Load: multipart upload concurrency (tier-2, local providers)"
	@echo "  test-load-soak     - Soak: long-running external binary (requires running gateway)"
	@echo "  test-load-baseline - Soak: update regression baselines"
	@echo "  test-load-prometheus-Soak: load tests with Prometheus metrics"
	@echo "  test-load-minio    - Soak: auto-manage MinIO + gateway environment"
	@echo "  test-load-garage   - Soak: auto-manage Garage + gateway environment"
	@echo "  test-rotation      - Run key rotation conformance tests (tier-2, all providers)"
	@echo "  build-loadtest     - Build load test binary"
	@echo "  test-all           - Run all tests including integration"
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
