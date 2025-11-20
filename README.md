# Heimdall

[![CI](https://github.com/travisbale/heimdall/actions/workflows/ci.yml/badge.svg)](https://github.com/travisbale/heimdall/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/travisbale/heimdall)](https://goreportcard.com/report/github.com/travisbale/heimdall)
[![Go Version](https://img.shields.io/badge/go-1.25-blue.svg)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Authentication and authorization service written in Go. Handles user accounts, password hashing (Argon2), JWT issuance and validation, and multi-tenant access control for all tenant applications.

## Features

- **JWT Authentication** - RSA-signed tokens with user and tenant claims
- **Password Security** - Argon2id hashing with OWASP-recommended parameters
- **Email Verification** - Registration flow with email verification via mailman
- **Password Reset** - Secure token-based password reset via email
- **Account Lockout** - Progressive lockout after failed login attempts (5, 10, 15, 20 thresholds)
- **OAuth/OIDC Login** - Support for Google, Microsoft, GitHub, and custom OIDC providers
- **Corporate SSO** - Enterprise SSO with auto-provisioning and domain restrictions
- **RBAC** - Role-based access control with permissions, roles, and user assignments
- **Multi-tenancy** - Row-Level Security (RLS) for tenant isolation
- **Structured Logging** - Event constants for audit trails and observability
- **Health Checks** - Database connectivity monitoring (200 OK / 503 Service Unavailable)
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

### Database Cleanup

```bash
# Clean up expired tokens and old unverified accounts
./bin/heimdall cleanup --database-url "postgres://..."

# Customize unverified account age threshold (default: 7 days)
./bin/heimdall cleanup --database-url "postgres://..." --unverified-user-age-days 30
```

### Running the Service

```bash
./bin/heimdall start \
  --database-url "postgres://heimdall:password@localhost:5432/heimdall?sslmode=disable" \
  --http-address ":8080" \
  --grpc-address ":9090" \
  --jwt-private-key "/path/to/private-key.pem" \
  --jwt-public-key "/path/to/public-key.pem" \
  --jwt-expiration "24h" \
  --public-url "http://localhost:8080" \
  --mailman-grpc-address "localhost:50051" \
  --environment "development"
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

**Public Endpoints:**

- `HEAD /healthz` - Health check (returns 200 OK if healthy, 503 if database unavailable)
- `GET /v1/oauth/supported-types` - List supported OAuth provider types

**Authentication:**

- `POST /v1/register` - Register new user (sends verification email)
- `POST /v1/verify-email` - Verify email address
- `POST /v1/login` - Authenticate user, returns JWT
- `POST /v1/logout` - Logout (invalidates refresh token)
- `POST /v1/refresh` - Refresh access token using refresh token cookie

**Password Reset:**

- `POST /v1/forgot-password` - Request password reset (sends email)
- `POST /v1/reset-password` - Reset password with token

**OAuth/OIDC Authentication:**

- `POST /v1/oauth/login` - Start individual OAuth login (Google, Microsoft, GitHub)
- `POST /v1/oauth/sso` - Start corporate SSO login by email domain
- `GET /v1/oauth/callback` - OAuth callback endpoint (handles both flows)

**OIDC Provider Management** (requires authentication):

- `POST /v1/oauth/providers` - Create OIDC provider with dynamic registration
- `GET /v1/oauth/providers` - List all OIDC providers for tenant
- `GET /v1/oauth/providers/{id}` - Get OIDC provider details
- `PUT /v1/oauth/providers/{id}` - Update OIDC provider configuration
- `DELETE /v1/oauth/providers/{id}` - Delete OIDC provider

**RBAC** (requires authentication):

- `GET /v1/permissions` - List all system permissions
- `POST /v1/roles` - Create role
- `GET /v1/roles` - List roles for tenant
- `GET /v1/roles/{id}` - Get role details
- `PUT /v1/roles/{id}` - Update role
- `DELETE /v1/roles/{id}` - Delete role
- `GET /v1/roles/{id}/permissions` - Get role permissions
- `PUT /v1/roles/{id}/permissions` - Set role permissions
- `GET /v1/users/{id}/roles` - Get user roles
- `PUT /v1/users/{id}/roles` - Set user roles
- `GET /v1/users/{id}/permissions` - Get user direct permissions
- `PUT /v1/users/{id}/permissions` - Set user direct permissions

### gRPC (Port 9090)

- `CreateUser(email, tenant_id, role_ids)` - Create user in tenant with roles
  - Returns: user_id, email, tenant_id, verification_token
- `GetUserByID(user_id)` - Retrieve user by ID (used by other services)

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
├── cmd/heimdall/          # CLI commands (start, migrate, cleanup, version)
├── crypto/                # Cryptographic utilities
│   ├── aes/              # AES encryption for sensitive data
│   └── argon2/           # Argon2id password hashing
├── identity/              # Tenant context utilities
├── internal/
│   ├── api/              # HTTP and gRPC handlers
│   │   ├── http/         # HTTP REST API handlers (auth, OIDC, RBAC)
│   │   └── grpc/         # gRPC service implementation
│   ├── app/              # Server setup and lifecycle
│   ├── auth/             # Authentication/authorization service layer and domain models
│   ├── events/           # Event constants for structured logging and audit trails
│   ├── db/postgres/      # Database layer with RLS
│   │   ├── migrations/   # SQL schema migrations
│   │   ├── queries/      # SQL queries (input to sqlc)
│   │   └── internal/sqlc/# Generated type-safe queries
│   ├── email/            # Email service integrations
│   │   ├── mailman/      # Mailman gRPC client
│   │   └── console/      # Console email stub (development)
│   ├── oidc/             # OIDC provider implementations
│   └── pb/               # Generated protobuf code
├── jwt/                   # JWT token issuance and validation
├── sdk/                   # Client SDK and route definitions
├── proto/                 # Protocol Buffer definitions
├── .github/
│   ├── workflows/        # CI/CD pipelines
│   └── dependabot.yml    # Dependency automation
├── Dockerfile             # Multi-stage Docker build
├── Makefile               # Build commands
└── sqlc.yaml              # sqlc configuration
```

## Security Considerations

- **Argon2id** - Memory-hard password hashing (64MB, 2 iterations, 4 threads)
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
- `JWT_PUBLIC_KEY_PATH` - Path to RSA public key (PEM format)
- `JWT_EXPIRATION` - Refresh token lifetime (default: `24h`)
- `PUBLIC_URL` - Base URL for email verification and password reset links (default: `http://localhost:8080`)
- `MAILMAN_GRPC_ADDRESS` - Mailman gRPC address (default: `localhost:50051`)
- `ENVIRONMENT` - Environment name: `development`, `staging`, `production` (default: `development`)
- `CORS_ALLOWED_ORIGINS` - Comma-separated list of allowed CORS origins
- `ENCRYPTION_KEY` - 32-byte hex key for encrypting sensitive data (OIDC client secrets)

## License

See LICENSE file.
