.PHONY: build dev test clean sqlc protoc fmt lint tidy download docker-build migrate-up migrate-down help

# Build production binary
build:
	@echo "Building production binary..."
	@CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o bin/heimdall ./cmd/heimdall
	@echo "Build complete: bin/heimdall"

# Development build (faster, debug symbols)
dev:
	@echo "Building development binary..."
	@go build -o bin/heimdall ./cmd/heimdall
	@echo "Build complete: bin/heimdall"

# Run all tests
test:
	@echo "Running tests..."
	@go test -v -race ./...

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@go clean
	@rm -rf bin

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@go run golang.org/x/tools/cmd/goimports@v0.38.0 -w $(shell \
		find . -type f -name '*.go' \
			-not -path './internal/pb/*' \
			-not -path './internal/db/*' )

# Lint code
lint:
	@echo "Linting code..."
	@docker run -t --rm -v $(shell pwd):/app -w /app golangci/golangci-lint:v2.6.0 golangci-lint run

# Generate sqlc code (uses version from go.mod)
sqlc:
	@echo "Generating sqlc code..."
	@docker run --rm -v $(shell pwd):/src -w /src sqlc/sqlc generate

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

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# Run database migrations up
migrate-up:
	@./bin/heimdall migrate up

# Run database migrations down
migrate-down:
	@./bin/heimdall migrate down

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
	@echo "  test           - Run all tests"
	@echo "  clean          - Clean build artifacts"
	@echo "  deps           - Install and tidy Go dependencies"
	@echo "  sqlc           - Generate sqlc code from queries"
	@echo "  protoc         - Generate protobuf/gRPC code"
	@echo "  migrate-up     - Apply database migrations"
	@echo "  migrate-down   - Roll back latest migration"
	@echo ""
	@echo "Development:"
	@echo "  fmt            - Format code"
	@echo "  lint           - Lint code"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build   - Build Docker image"
	@echo ""
	@echo "  help           - Display this help message"
