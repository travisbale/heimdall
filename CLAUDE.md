# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Heimdall is a Go authentication and authorization service: user accounts, Argon2id password
hashing, RSA-signed JWTs, MFA, OIDC/SSO, RBAC, and multi-tenant isolation. It serves an HTTP
API for browsers and a gRPC API for other services, and it is the only issuer of tokens on
the platform — every other service verifies them with its public key.

Consumers in this workspace: `manitoba-ryder-cup/scorecard` (verifies tokens, defines its own
`scorecard:` scopes) and `manitoba-ryder-cup/web` (logs in through the edge at
`/api/auth/*`). Shared primitives come from `travisbale/knowhere`.

## Common Commands

```sh
make dev            # development binary (runs make fmt first)
make build          # production binary (static, stripped)
make fmt            # gofmt, goimports, then gci to enforce import grouping
make lint            # golangci-lint via Docker, same version as CI
make sqlc           # regenerate internal/db/postgres/internal/sqlc from queries/
make protoc         # regenerate internal/pb from proto/
make unit           # unit tests, no Docker
make test-setup     # build and start postgres + oidc-mock + heimdall, run migrations
make integration    # run ./test/... against that stack
make test           # test-setup + unit + integration
make coverage       # HTML coverage report from the unit run
make test-teardown  # stop the stack and drop its volumes
```

CI runs eight jobs: format, lint, build, test, govulncheck, codegen drift, Docker build, and
a migrate up/down/up cycle against a live Postgres. `setup-go` reads `go-version-file: go.mod`
with `check-latest: true` — without `check-latest` it settles for whatever patch the runner
image has cached, which is how a fixed stdlib CVE kept failing the security job.

The format job runs `make fmt` and fails on a diff, so run it before pushing. It does more
than gofmt: goimports resolves the imports a file needs, and gci then enforces their
grouping, which goimports will not — it treats a blank line as deliberate and preserves it.
`gofmt -l` reports a clean tree that CI then rejects.

## Architecture

```txt
cmd/heimdall/            # CLI entry point (urfave/cli): start, migrate, cleanup, version
internal/app/            # Lifecycle and dependency wiring
  ├── server.go          # Builds everything, coordinates HTTP + gRPC + DB shutdown
  ├── services.go        # Constructs the iam services and wires their dependencies
  ├── databases.go       # Constructs the repositories
  └── setup.go, config.go, oidc_providers.go

internal/api/rest/       # HTTP layer (stdlib ServeMux, method-prefixed patterns)
internal/api/grpc/       # gRPC layer (CreateUser, GetUserByID for internal services)
internal/iam/            # Domain layer: services, models, sentinel errors, scopes
internal/password/       # Password policy (length, common list, HIBP)
internal/oidc/, mfa/totp/, email/, events/
internal/db/postgres/    # Repositories, migrations, sqlc queries
sdk/                     # Public contract: DTOs, route constants, HTTP and gRPC clients
test/                    # Integration suite, grouped by feature
```

### Service Wiring

`iam` services are plain structs with exported fields and **no constructors**. `app/services.go`
is the single place they are assembled. A missing dependency is a nil field and panics on
first use — deliberately, because a service silently skipping a check it was supposed to run
is worse than a crash at startup. Do not add nil guards that make an unwired dependency
behave like a disabled feature.

Two wiring details are load-bearing:

- `passwordValidator` is built **once** and shared. `NewValidator` builds the common-password
  map, so a per-call validator rebuilds it on every request.
- `passwordService.SessionRevoker` is assigned after `sessionService` exists — a cycle broken
  by ordering, because a password change has to end the sessions the old password created.

### Multi-Tenancy and When the Tenant Is Unknown

Tenant-scoped tables carry both `ENABLE` and `FORCE ROW LEVEL SECURITY`. **`FORCE` is
load-bearing** — Postgres exempts a table's owner from its own policies, and the application
role owns every table because it runs the migrations.

The distinction that makes this service different from the ones behind it: **authentication
resolves the tenant, so the login path cannot assume one.** `GetUserByEmail` and `GetUser`
run under `WithTransaction` (no tenant context) because at that point the tenant is the
*output* of the query. Tenant-scoped administration — `CreateUser`, `DeleteUser`, roles,
providers — uses `WithTenantContext`. Choosing the wrong one either leaks across tenants or
makes login impossible, and neither fails loudly.

Pre-auth and global tables carry no RLS at all: `permissions` is platform-wide by design (see
below), and `login_attempts`, `verification_tokens` and `password_reset_tokens` are reached
by a bearer token or an email address, before any tenant is known.

### Permission Naming

`permissions` is global, not tenant-scoped, and every service on the platform registers its
scopes into it. Names are therefore namespaced by owning service:

```
heimdall:user:create          Heimdall's own
scorecard:tournaments:write   a consumer's
```

`permissions.name` is `UNIQUE`, so an unprefixed name squats on one another service will
want and the second seeder to claim it fails.

Heimdall's own scopes are declared once in `iam.AllScopes` and seeded by migration
`003_seed_permissions`. `test/rbac/roles_test.go` asserts the two match exactly, so adding a
scope to one without the other fails the build. Scope checks are exact string comparison —
`heimdall:*` grants nothing.

### Routes and the SDK

`sdk/routes.go` holds every path constant and `rest/router.go` registers from them, so there
are no path literals in the routing table and a route change is a compile-time concern. Keep
it that way.

`Router` implements `http.Handler` and builds its routes and middleware under a `sync.Once`
on first request. The global chain, outermost first: CORS (only when origins are configured),
recover, `RequireProxySecret`, request ID, client IP, user agent.

Per-route wrappers are the four closures at the top of `registerRoutes` — `public`, `limit`,
`auth`, `require`. Adding a route means picking one, not writing a new chain.

### Password Policy

The whole rule lives in `internal/password`: length in runes, then the common-password list,
then Have I Been Pwned via k-anonymity. A failed HIBP lookup **accepts** the password — a
password reset must not hinge on a third party being reachable.

`Validate` returns sentinels (`ErrTooShort`, `ErrTooLong`, `ErrTooCommon`, `ErrBreached`),
never client-facing wording. `rest.passwordRejection` is the one place those become a message.
Services wrap the result in `iam.ErrWeakPassword`, which the boundary maps to 400.

**The SDK does not pre-validate passwords.** Request `Validate` methods check shape (required
fields, email format); policy is the server's alone. Splitting it meant a client-side length
rule and a server-side strength rule enforcing halves of the same thing, with nothing keeping
them equal. This package lives under `internal/` on purpose: it is Heimdall's policy, not a
reusable primitive, which is why it was moved out of knowhere.

### Rate Limiting

`rateLimitMiddleware` gives each route its own in-memory `ulule/limiter` instance. Two things
about it:

- The key is `identity.GetIPAddress`, set via `stdlib.WithKeyGetter`. The library's default
  key is `RemoteAddr`, which behind a proxy is the proxy — one bucket shared by every client
  on earth. That was the bug; the fix is that one option, not a hand-rolled middleware.
- Getting a real client IP requires `TRUSTED_PROXY_MODE`, which makes `identity.ClientIP`
  read the rightmost `X-Forwarded-For` entry. Without it every request keys on the proxy again.

The store is per-process memory, so limits are per instance and reset on deploy. That is
accepted: this is a backstop against a script hammering one container, and the real volume
defence is the Cloudflare edge in front of it. A shared Postgres store was built and reverted
— it put a write on the unauthenticated path to defend against unauthenticated writes.

Rate limiting is skipped when `ENVIRONMENT=test`, which the integration stack sets.

### Sessions and Refresh Tokens

Refresh tokens rotate on every use and are tracked by family. Replaying a revoked token
revokes the whole family, on the theory that a replay means both parties hold it and neither
can be told apart. Separate logins get independent families, so one compromised session does
not sign the user out everywhere.

Bearer secrets — reset tokens, device tokens — are stored **hashed**. The user holds the
plaintext; a leaked table, backup or replica must not yield working credentials.

The refresh cookie's `Path` is `X-Forwarded-Prefix` + `sdk.RouteV1Refresh`, which is what
lets the web client's edge proxy re-anchor it under `/api/auth`. Changing either side without
the other silently breaks refresh — the browser simply stops sending the cookie, and the
symptom is being logged out after the access token expires rather than any error.

## Error Handling

Sentinels live in `internal/iam/errors.go` and name the condition, not the layer:
`ErrWeakPassword`, not `ErrInvalidPassword` — the latter reads like a failed login. Handlers
map sentinels to statuses; internal error text does not reach the client.

## Testing

- Unit tests cover `internal/iam`, `internal/password` and the like; `make unit` excludes
  `api`, `db`, `pb`, `cmd`, `email` and `test`, which need infrastructure.
- Integration tests in `test/` drive the running service over HTTP, grouped by feature
  (`password`, `rbac`, `session`, `mfa`, `oidc`, `isolation`). Shared helpers in `test/_util`.
- `test/isolation/` is the cross-tenant suite — every table with an RLS policy should have a
  case proving one tenant cannot read another's rows.
- A change to the domain and its integration test both passing proves nothing if the stack
  is stale: `make test-setup` rebuilds the image, and skipping it runs the new test against
  the old binary.

## Configuration

Environment variables (all have `--flag` equivalents; see `cmd/heimdall/flags.go`):

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | — | PostgreSQL connection string |
| `HTTP_ADDRESS` | `:8080` | |
| `GRPC_ADDRESS` | `:9090` | |
| `JWT_ISSUER` | `heimdall` | |
| `JWT_PRIVATE_KEY_PATH` / `JWT_PUBLIC_KEY_PATH` | — | RSA keypair, PEM |
| `ACCESS_TOKEN_EXPIRATION` | `15m` | |
| `REFRESH_TOKEN_EXPIRATION` | `24h` | Session lifetime before re-authentication |
| `PUBLIC_URL` | `http://localhost:8080` | Base for verification and reset links |
| `ENVIRONMENT` | `development` | `test` disables rate limiting |
| `TRUSTED_PROXY_MODE` | `false` | Required for correct client IPs behind an edge |
| `PROXY_SECRET` | empty | Requires `X-Proxy-Secret` on everything but `/health` |
| `CORS_ALLOWED_ORIGINS` | empty | Comma-separated |
| `ENCRYPTION_KEY` | — | 32-byte hex; OIDC client secrets and TOTP secrets |
| `TOTP_PERIOD` | `30` | Seconds |
| `EMAIL_WEBHOOK_URL` / `MAILMAN_GRPC_ADDRESS` | empty | Neither set logs tokens to stdout |

## Development Guidelines

- Keep comments minimal and focused on *why*. The code should speak for itself; do not
  narrate what a function does. One line where at all possible. Write for someone who
  never saw the change: "used to" earns its place only where it warns off a path they
  might take again, and anything else about how the code got this way is a commit message.
- No `Co-Authored-By` trailer and no generated-with footer, in commits or PR descriptions.
  The repo squash-merges with the PR body as the message, so anything in it lands in the
  log — write PR descriptions as prose for that reason.
- Generated trees (`internal/db/postgres/internal/sqlc`, `internal/pb`) are never hand-edited;
  CI regenerates and fails on drift.
- Never move a published tag. A Go module is published by tagging, and `sum.golang.org`
  records the hash it first saw permanently — a moved tag becomes a checksum mismatch for
  every consumer.
- Changes to `sdk/` are a contract change for scorecard and web. Grep the sibling repos before
  altering a wire type or route constant.
