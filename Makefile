.PHONY: build dev test test-setup test-teardown unit integration coverage clean sqlc protoc fmt lint docker-build help

# Version is derived from git tags
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@go run golang.org/x/tools/cmd/goimports@v0.38.0 -w $(shell \
		find . -type f -name '*.go' \
			-not -path './internal/pb/*' \
			-not -path './internal/db/*' )

# Development build (faster, debug symbols)
dev: fmt
	@echo "Building development binary..."
	@go build -ldflags="-X 'main.Version=$(VERSION)'" -o bin/heimdall ./cmd/heimdall
	@echo "Build complete: bin/heimdall"

# Build production binary
build: fmt
	@echo "Building production binary..."
	@CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s -X 'main.Version=$(VERSION)'" -o bin/heimdall ./cmd/heimdall
	@echo "Build complete: bin/heimdall"

# Run unit tests only
unit:
	@echo "Running unit tests..."
	@go test -race -coverprofile=coverage.out -covermode=atomic \
		$$(go list ./... | grep -v -e '/internal/api' -e '/internal/db' -e '/internal/pb' -e '/cmd/' -e '/internal/email' -e '/test/')
	@echo "Unit test coverage: $$(go tool cover -func=coverage.out | grep total | awk '{print $$3}')"

# Generate HTML coverage report
coverage: test
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@go clean
	@rm -rf bin
	@rm -f coverage.out coverage.html

# Generate RSA keys for test infrastructure (one-time setup)
test-keys:
	@if [ ! -f test/keys/private-key.pem ]; then \
		echo "Generating test RSA keys..."; \
		mkdir -p test/keys; \
		openssl genrsa -out test/keys/private-key.pem 2048 2>/dev/null; \
		openssl rsa -in test/keys/private-key.pem -pubout -out test/keys/public-key.pem 2>/dev/null; \
		chmod 644 test/keys/*.pem; \
		echo "Test keys generated in test/keys/"; \
	else \
		echo "Test keys already exist, skipping generation"; \
	fi

# Start test infrastructure (postgres, oidc-mock, heimdall)
test-setup: test-keys
	@echo "Building heimdall image..."
	@docker compose -f test/docker-compose.yml build
	@echo "Starting postgres and oidc-mock..."
	@docker compose -f test/docker-compose.yml up -d --wait postgres oidc-mock
	@echo "Waiting for OIDC mock to be ready..."
	@until curl -sf http://localhost:8082/.well-known/openid-configuration > /dev/null 2>&1; do sleep 1; done
	@echo "Starting heimdall..."
	@docker compose -f test/docker-compose.yml up -d --wait heimdall || \
		(echo "Heimdall failed to start. Logs:" && \
		docker compose -f test/docker-compose.yml logs heimdall && exit 1)
	@echo "Running migrations..."
	@docker compose -f test/docker-compose.yml exec -T heimdall ./heimdall migrate up > /dev/null
	@echo "Test infrastructure ready"

# Run integration tests only (requires test infrastructure to be running)
integration:
	@echo "Running integration tests..."
	@go test -short -count=1 -timeout 5m ./test/... || \
		(echo "Integration tests failed. Logs written to test/heimdall.log" && \
		docker compose -f test/docker-compose.yml logs heimdall > test/heimdall.log 2>&1 && exit 1)

# Run all tests (unit + integration, requires Docker)
test: test-setup unit integration

# Stop and remove test infrastructure
test-teardown:
	@echo "Tearing down test infrastructure..."
	@docker compose -f test/docker-compose.yml down -v --remove-orphans
	@echo "Test infrastructure removed"

# Lint code
lint:
	@echo "Linting code..."
	@docker run -t --rm -v $(shell pwd):/app -w /app golangci/golangci-lint:v2.11.4 golangci-lint run

sqlc:
	@echo "Generating sqlc code..."
	@docker run --rm --user $(shell id -u):$(shell id -g) -v $(shell pwd):/src -w /src sqlc/sqlc:1.31.0 generate

# Generate protobuf code
protoc:
	@echo "Generating protobuf code..."
	@docker build -q -t go-protoc:latest -f proto/Dockerfile . > /dev/null
	@docker run --rm -v $(shell pwd):/proto --user $(shell id -u):$(shell id -g) \
		-w /proto \
		go-protoc:latest \
		-I proto \
		--go_out=internal/pb --go_opt=paths=source_relative \
		--go-grpc_out=internal/pb --go-grpc_opt=paths=source_relative \
		proto/*.proto

# Docker targets
docker-build:
	@echo "Building Docker image..."
	@docker build -t heimdall:dev .

# Display help
help:
	@echo "Available targets:"
	@echo "  build          - Build production binary"
	@echo "  dev            - Build with debug symbols (faster compilation)"
	@echo "  run            - Build and run the service"
	@echo "  test           - Run all tests (setup + run + teardown)"
	@echo "  test-setup     - Start test infrastructure (postgres, oidc-mock, heimdall)"
	@echo "  test-teardown  - Stop and remove test infrastructure"
	@echo "  unit           - Run unit tests only"
	@echo "  coverage       - Generate HTML coverage report"
	@echo "  clean          - Clean build artifacts"
	@echo "  sqlc           - Generate sqlc code from queries"
	@echo "  protoc         - Generate protobuf/gRPC code"
	@echo ""
	@echo "Development:"
	@echo "  fmt            - Format code"
	@echo "  lint           - Lint code"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build   - Build Docker image"
	@echo ""
	@echo "  help           - Display this help message"
