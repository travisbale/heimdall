.PHONY: fmt lint unit test-keys test-setup integration test test-teardown coverage dev build sqlc protoc docker-build clean help

# Version is derived from git tags
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Every target that formats or checks formatting works on this set: everything but the
# generated protobuf and sqlc packages.
GO_FILES = $(shell find . -type f -name '*.go' -not -path './internal/pb/*' -not -path './internal/db/*')

# --- Quality ---------------------------------------------------------------------------

# gci runs after goimports because goimports treats a blank line as deliberate grouping
# and preserves it, so a stray one inside the stdlib block survives formatting. gci
# enforces the two sections instead of respecting what it finds.
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@go run golang.org/x/tools/cmd/goimports@v0.48.0 -w $(GO_FILES)
	@go run github.com/daixiang0/gci@v0.13.7 write --skip-generated -s standard -s default $(GO_FILES) >/dev/null

# Lint code
lint:
	@echo "Linting code..."
	@docker run -t --rm -v $(shell pwd):/app -w /app golangci/golangci-lint:v2.12.2 golangci-lint run

# --- Tests -----------------------------------------------------------------------------

# Run unit tests only
unit:
	@echo "Running unit tests..."
	@go test -race -coverprofile=coverage.out -covermode=atomic \
		$$(go list ./... | grep -v -e '/internal/db' -e '/internal/pb' -e '/cmd/' -e '/internal/email' -e '/test/')
	@echo "Unit test coverage: $$(go tool cover -func=coverage.out | grep total | awk '{print $$3}')"

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
	@echo "Running migrations..."
	@docker compose -f test/docker-compose.yml run --rm heimdall migrate up
	@echo "Starting heimdall..."
	@docker compose -f test/docker-compose.yml up -d --wait heimdall || \
		(echo "Heimdall failed to start. Logs:" && \
		docker compose -f test/docker-compose.yml logs heimdall && exit 1)
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

# Generate HTML coverage report from the unit run
coverage: unit
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# --- Build -----------------------------------------------------------------------------

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

# --- Code generation -------------------------------------------------------------------

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

# --- Docker ----------------------------------------------------------------------------

# Docker targets
docker-build:
	@echo "Building Docker image..."
	@docker build -t heimdall:dev .

# --- Housekeeping ----------------------------------------------------------------------

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@go clean
	@rm -rf bin
	@rm -f coverage.out coverage.html

# Display help
help:
	@echo "Quality:"
	@echo "  fmt            - Format code (gofmt, goimports, gci)"
	@echo "  lint           - Lint code"
	@echo ""
	@echo "Tests:"
	@echo "  unit           - Run unit tests with coverage (no infrastructure)"
	@echo "  test-keys      - Generate test JWT RSA keys (one-time)"
	@echo "  test-setup     - Start postgres, oidc-mock and heimdall"
	@echo "  integration    - Run the integration suite (needs test-setup first)"
	@echo "  test           - test-setup + unit + integration"
	@echo "  test-teardown  - Stop test infra and remove volumes"
	@echo "  coverage       - HTML coverage report from the unit run"
	@echo ""
	@echo "Build:"
	@echo "  dev            - Build with debug symbols (faster compilation)"
	@echo "  build          - Build production binary"
	@echo ""
	@echo "Code generation:"
	@echo "  sqlc           - Generate sqlc code from queries"
	@echo "  protoc         - Generate protobuf/gRPC code"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build   - Build Docker image"
	@echo ""
	@echo "Housekeeping:"
	@echo "  clean          - Clean build artifacts"
	@echo "  help           - Display this help message"
