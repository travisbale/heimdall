<p align="center">
  <img src="logo.png" alt="Heimdall" width="350" />
</p>
<p align="center">
  <a href="https://github.com/travisbale/heimdall/actions/workflows/ci.yml"><img src="https://github.com/travisbale/heimdall/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://goreportcard.com/report/github.com/travisbale/heimdall"><img src="https://goreportcard.com/badge/github.com/travisbale/heimdall" alt="Go Report Card" /></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/go-1.26-blue.svg" alt="Go Version" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License" /></a>
</p>

Authentication and authorization service written in Go. Handles user accounts, password hashing (Argon2), JWT issuance and validation, and multi-tenant access control for all tenant applications.

Named after [Heimdall](https://en.wikipedia.org/wiki/Heimdall_(character)), the all-seeing guardian of the Bifrost who protects the realms from unwanted intrusion.

## Features

- **JWT Authentication** - RSA-signed tokens with user and tenant claims
- **Password Security** - Argon2id hashing with OWASP-recommended parameters
- **Multi-Factor Authentication (MFA)** - TOTP-based MFA with backup codes for enhanced security
- **Trusted Devices** - Users can mark devices as trusted to skip MFA (30-day sliding window)
- **Required MFA Enforcement** - Roles can require MFA; users are guided through setup on first login
- **Session Management** - List active sessions, revoke individual sessions, or sign out everywhere
- **Refresh Token Rotation** - Family-based tracking with automatic theft detection
- **Email Verification** - Registration flow with pluggable email delivery (webhook, mailman, or console logging)
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

- Go 1.26+
- PostgreSQL 16+
- protoc (Protocol Buffers compiler)
- Docker (required for linting, integration tests, and code generation)

### Setup

```bash
# Install dependencies
make deps

# Generate code (sqlc + protobuf)
make sqlc
make protoc

# Build development binary
make dev

# Format code
make fmt

# Run linters
make lint

# Run unit tests only (no Docker needed)
make unit

# Run all tests including integration (requires Docker)
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
  --environment "development"
```

With no email configuration, tokens are logged to stdout (console mode). To send emails via webhook:

```bash
./bin/heimdall start ... --email-webhook-url "https://your-email-service/api/send"
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
- `DELETE /v1/refresh` - Logout (invalidates refresh token)
- `POST /v1/refresh` - Refresh access token (rotates refresh token)

**Session Management:**

- `GET /v1/sessions` - List active sessions with metadata (IP, user agent, timestamps)
- `DELETE /v1/sessions` - Revoke all sessions (sign out everywhere)
- `DELETE /v1/sessions/{id}` - Revoke specific session

**Password Reset:**

- `POST /v1/forgot-password` - Request password reset (sends email)
- `POST /v1/reset-password` - Reset password with token

**Multi-Factor Authentication (MFA):**

- `POST /v1/mfa/verify` - Verify MFA code during login (can trust device)
- `POST /v1/mfa/setup` - Initiate MFA setup (returns QR code and backup codes)
- `POST /v1/mfa/enable` - Enable MFA after validating TOTP code
- `DELETE /v1/mfa/disable` - Disable MFA (requires password and TOTP/backup code)
- `POST /v1/mfa/backup-codes/regenerate` - Regenerate backup codes (requires password)
- `GET /v1/mfa/status` - Get MFA status and remaining backup codes
- `POST /v1/mfa/required-setup` - Start MFA setup when role requires it (uses setup token)
- `POST /v1/mfa/required-enable` - Enable MFA and complete login flow

**OAuth/OIDC Authentication:**

- `POST /v1/oauth/login` - Start individual OAuth login (Google, Microsoft, GitHub)
- `POST /v1/sso/login` - Start corporate SSO login by email domain
- `GET /v1/oauth/callback` - OAuth callback endpoint (handles both flows)

**OIDC Provider Management** (requires authentication):

- `POST /v1/oauth/providers` - Create OIDC provider with dynamic registration
- `GET /v1/oauth/providers` - List all OIDC providers for tenant
- `GET /v1/oauth/providers/{id}` - Get OIDC provider details
- `PUT /v1/oauth/providers/{id}` - Update OIDC provider configuration
- `DELETE /v1/oauth/providers/{id}` - Delete OIDC provider

**User Profile:**

- `GET /v1/users/me` - Get current user profile

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

## Testing

The project has both unit tests and integration tests:

- **Unit tests** (`make unit`) - Fast, no external dependencies
- **Integration tests** (`make test`) - Full end-to-end tests using testcontainers (PostgreSQL + mock OIDC server). Requires Docker.

The integration test suite covers authentication, RBAC, MFA, sessions, OIDC/SSO flows, tenant isolation, and server-side input validation.

## CI/CD Pipeline

The project uses GitHub Actions for continuous integration:

### Automated Checks

1. **Linting** - `golangci-lint`
2. **Build** - Compile and verify binary works
3. **Tests** - Unit and integration tests with race detector (includes testcontainers)
4. **Security** - `govulncheck` for known vulnerabilities
5. **Code Generation** - Verify sqlc/protobuf are up-to-date
6. **Docker Build** - Validate Dockerfile builds
7. **Migrations** - Test SQL migrations against PostgreSQL

### Dependabot

Automated dependency updates run weekly for:

- Go modules
- Docker base images
- GitHub Actions versions

## Security Considerations

### Authentication & Cryptography

- **Argon2id** - Memory-hard password hashing (64MB, 2 iterations, 4 threads)
- **JWT RSA signatures** - Asymmetric keys for token signing/verification
- **Constant-time comparison** - Prevents timing attacks on passwords
- **HTTPS recommended** - For production deployments

### Token Rotation & Theft Detection

Refresh tokens use family-based rotation to detect and respond to token theft:

1. Each login creates a new token family (UUID)
2. On refresh, the old token is revoked and a new one is issued with the same family ID
3. If a revoked token is replayed (theft attempt), the entire token family is revoked
4. Separate logins create independent families, so one compromised session doesn't affect others

This provides defense-in-depth: even if an attacker steals a refresh token, using it after the legitimate user refreshes will invalidate all tokens in that family.

### Trusted Device Security

Trusted devices allow users to skip MFA on recognized devices:
- Device tokens are hashed (SHA-256) before storage
- Tokens have 30-day expiration with sliding window (extends on use)
- Automatically revoked on: sign out everywhere, password change, token reuse detection
- Token prefix (`hmdl_device_`) enables secret scanning detection

### Multi-Tenant Isolation

- **Row-Level Security (RLS)** - Database-enforced tenant isolation at the PostgreSQL layer
- **JOIN-based RLS policies** - Junction tables use EXISTS subqueries to validate entity relationships:

```sql
-- Example: user_roles table RLS policy
CREATE POLICY tenant_isolation_policy ON user_roles
    FOR ALL TO PUBLIC
    USING (EXISTS (
        SELECT 1 FROM users WHERE users.id = user_roles.user_id
    ) AND EXISTS (
        SELECT 1 FROM roles WHERE roles.id = user_roles.role_id
    ));
```

This approach provides:

- **Normalized schema** - No redundant `tenant_id` in junction tables
- **Referential integrity** - Prevents cross-tenant associations (e.g., assigning Tenant A's role to Tenant B's user)
- **Defense in depth** - Database blocks invalid operations even if application code has bugs
- **Security by design** - RLS filtering happens automatically on parent tables

### Container Security

- **Non-root container** - Docker runs as `heimdall:heimdall` (uid 1000)

## Configuration

Environment variables:

- `DATABASE_URL` - PostgreSQL connection string
- `HTTP_ADDRESS` - HTTP server address (default: `:8080`)
- `GRPC_ADDRESS` - gRPC server address (default: `:9090`)
- `JWT_ISSUER` - JWT issuer name (default: `heimdall`)
- `JWT_PRIVATE_KEY_PATH` - Path to RSA private key (PEM format)
- `JWT_PUBLIC_KEY_PATH` - Path to RSA public key (PEM format)
- `JWT_EXPIRATION` - Refresh token lifetime (default: `24h`)
- `PUBLIC_URL` - Base URL for email verification and password reset links (default: `http://localhost:8080`)
- `ENVIRONMENT` - Environment name: `development`, `staging`, `production` (default: `development`)
- `TRUSTED_PROXY_MODE` - Enable IP extraction from X-Forwarded-For headers (default: `false`)
- `CORS_ALLOWED_ORIGINS` - Comma-separated list of allowed CORS origins
- `ENCRYPTION_KEY` - 32-byte hex key for encrypting sensitive data (OIDC client secrets, MFA TOTP secrets)
- `TOTP_PERIOD` - TOTP time window in seconds (default: `30`)

**Email Delivery** (if neither is set, tokens are logged to stdout):
- `EMAIL_WEBHOOK_URL` - HTTP webhook URL for email delivery (receives JSON POST with email events)
- `MAILMAN_GRPC_ADDRESS` - Mailman gRPC server address

**OAuth Provider Configuration** (optional):
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` - Google OAuth credentials
- `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, `MICROSOFT_TENANT_ID` - Microsoft OAuth credentials
- `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` - GitHub OAuth credentials

## License

See LICENSE file.
