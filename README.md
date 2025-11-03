# Heimdall

[![CI](https://github.com/travisbale/heimdall/actions/workflows/ci.yml/badge.svg)](https://github.com/travisbale/heimdall/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/travisbale/heimdall)](https://goreportcard.com/report/github.com/travisbale/heimdall)
[![Go Version](https://img.shields.io/badge/go-1.25-blue.svg)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Authentication and authorization service written in Go. Handles user accounts, password hashing (Argon2), JWT issuance and validation, and role-based access control for all tenant applications.

## Features

- **JWT Authentication** - RSA-signed tokens with user and tenant claims
- **Password Security** - Argon2id hashing with OWASP-recommended parameters
- **Multi-tenancy** - Row-Level Security (RLS) for tenant isolation
- **Dual APIs** - HTTP REST API and gRPC for service-to-service communication
- **Type-safe Database** - sqlc-generated queries with PostgreSQL + pgx

## Architecture

- **HTTP API** (port 8080) - Login/logout endpoints for user authentication
- **gRPC API** (port 9090) - User creation for internal services
- **Database Layer** - Context-based tenant isolation with RLS policies
- **Password Hashing** - Argon2id with secure parameters
- **JWT Tokens** - RSA signatures with configurable expiration

## Development

### Prerequisites

- Go 1.24+
- PostgreSQL 16+
- protoc (Protocol Buffers compiler)
- golangci-lint
- Docker (optional)

### Setup

```bash
# Install dependencies
make download

# Generate code (sqlc + protobuf)
make sqlc
make protoc

# Build development binary
make dev

# Run linters
make lint

# Format code
make fmt

# Run tests
make test
```

### Database Migrations

```bash
# Run migrations
./bin/heimdall migrate up --database-url "postgres://..."

# Rollback last migration
./bin/heimdall migrate down --database-url "postgres://..."

# Check migration version
./bin/heimdall migrate version --database-url "postgres://..."
```

### Running the Service

```bash
./bin/heimdall serve \
  --database-url "postgres://heimdall:password@localhost:5432/heimdall?sslmode=disable" \
  --http-address ":8080" \
  --grpc-address ":9090" \
  --jwt-private-key "/path/to/private-key.pem" \
  --jwt-expiration "24h"
```

### Docker

```bash
# Build image
docker build -t heimdall:latest .

# Run container
docker run -p 8080:8080 -p 9090:9090 \
  -e DATABASE_URL="postgres://..." \
  -e JWT_PRIVATE_KEY_PATH="/keys/private.pem" \
  heimdall:latest
```

## API Endpoints

### HTTP (Port 8080)

- `GET /healthz` - Health check (no auth)
- `POST /v1/login` - Authenticate user, returns JWT

  ```json
  {
    "email": "user@example.com",
    "password": "password"
  }
  ```

- `POST /v1/logout` - Logout (client-side token removal)

### gRPC (Port 9090)

- `CreateUser(email, tenant_id)` - Create user with temporary password
  - Returns: user_id, email, tenant_id, temporary_password

## CI/CD Pipeline

The project uses GitHub Actions for continuous integration:

### Automated Checks

1. **Linting** - `golangci-lint` with timeout
2. **Build** - Compile and verify binary works
3. **Tests** - Run with race detector and coverage
4. **Security** - `govulncheck` for known vulnerabilities
5. **Code Generation** - Verify sqlc/protobuf are up-to-date
6. **Docker Build** - Validate Dockerfile builds
7. **Migrations** - Test SQL migrations against PostgreSQL

### Pre-commit Hook

A Git pre-commit hook automatically runs:

- Code formatting (`make fmt`)
- Linting (`make lint`)
- Build verification (`make dev`)

This ensures code quality before commits.

### Dependabot

Automated dependency updates run weekly for:

- Go modules
- Docker base images
- GitHub Actions versions

## Project Structure

```txt
heimdall/
├── cmd/heimdall/          # CLI commands (serve, migrate, version)
├── internal/
│   ├── api/              # HTTP handlers and routes
│   ├── app/              # Server setup and lifecycle
│   ├── auth/             # JWT, password hashing, service layer
│   ├── db/postgres/      # Database layer with RLS
│   │   ├── migrations/   # SQL schema migrations
│   │   ├── queries/      # SQL queries (input to sqlc)
│   │   └── sqlc/         # Generated type-safe queries
│   ├── domain/           # Domain models and enums
│   ├── grpc/             # gRPC service implementation
│   └── tenant/           # Tenant context utilities
├── proto/                # Protocol Buffer definitions
├── .github/
│   ├── workflows/        # CI/CD pipelines
│   └── dependabot.yml    # Dependency automation
├── Dockerfile            # Multi-stage Docker build
├── Makefile              # Build commands
└── sqlc.yaml             # sqlc configuration
```

## Security Considerations

- **Argon2id** - Memory-hard password hashing (64MB, 1 iteration, 4 threads)
- **JWT RSA signatures** - Asymmetric keys for token signing/verification
- **Row-Level Security** - Database-enforced tenant isolation
- **Non-root container** - Docker runs as `heimdall:heimdall` (uid 1000)
- **Constant-time comparison** - Prevents timing attacks on passwords
- **HTTPS recommended** - For production deployments

## Configuration

Environment variables:

- `DATABASE_URL` - PostgreSQL connection string
- `HTTP_ADDRESS` - HTTP server address (default: `:8080`)
- `GRPC_ADDRESS` - gRPC server address (default: `:9090`)
- `JWT_PRIVATE_KEY_PATH` - Path to RSA private key (PEM format)
- `JWT_EXPIRATION` - Token lifetime (default: `24h`)

## License

See LICENSE file.
