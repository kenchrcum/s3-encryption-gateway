.PHONY: build test lint clean run docker-build docker-push help

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
		-o bin/$(BINARY_NAME) ./cmd/server

# Run tests
test:
	@echo "Running tests..."
	@go test -v -race -coverprofile=coverage.out ./...

# Run integration tests (requires Docker)
test-integration:
	@echo "Running integration tests..."
	@go test -v ./test/... -run TestS3Gateway

# Run load tests for range operations
test-load-range:
	@echo "Running range load tests..."
	@cd test && ./run_load_tests.sh --test-type range

# Run load tests for multipart operations
test-load-multipart:
	@echo "Running multipart load tests..."
	@cd test && ./run_load_tests.sh --test-type multipart

# Run all load tests
test-load: test-load-range test-load-multipart

# Run load tests and update baselines
test-load-baseline:
	@echo "Running load tests and updating baselines..."
	@cd test && ./run_load_tests.sh --update-baseline

# Run load tests with Prometheus metrics
test-load-prometheus:
	@echo "Running load tests with Prometheus metrics..."
	@cd test && ./run_load_tests.sh --prometheus http://localhost:9090

# Run load tests with automatic MinIO and Gateway management
test-load-minio:
	@echo "Running load tests with automatic MinIO and Gateway management..."
	@echo "This will start MinIO, the S3 Encryption Gateway, run tests, and clean up everything automatically."
	@echo "The environment will be completely removed even if tests are interrupted."
	@echo ""
	@cd test && ./run_load_tests.sh --manage-minio

# Build load test binary
build-loadtest:
	@echo "Building load test binary..."
	@go build -o bin/loadtest ./cmd/loadtest

# Run all tests including integration
test-all: test test-integration

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
	@echo "  test               - Run unit tests"
	@echo "  test-integration   - Run integration tests (requires Docker)"
	@echo "  test-load          - Run all load tests (range + multipart)"
	@echo "  test-load-range    - Run range operation load tests"
	@echo "  test-load-multipart- Run multipart operation load tests"
	@echo "  test-load-baseline - Run load tests and update baselines"
	@echo "  test-load-prometheus-Run load tests with Prometheus metrics"
	@echo "  test-load-minio    - Run load tests with MinIO environment management (auto cleanup)"
	@echo "  build-loadtest     - Build load test binary"
	@echo "  test-all           - Run all tests including integration"
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