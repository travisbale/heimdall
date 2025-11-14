package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
)

// UsersDB handles user database operations with tenant isolation
type UsersDB struct {
	db *DB
}

// NewUsersDB creates a new UsersDB instance
func NewUsersDB(db *DB) *UsersDB {
	return &UsersDB{db: db}
}

// CreateUser creates a new user
// Uses WithTransaction (not WithTenantContext) because registration happens pre-authentication
func (u *UsersDB) CreateUser(ctx context.Context, user *auth.User) (*auth.User, error) {
	var result *auth.User

	err := u.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbUser, err := q.CreateUser(ctx, sqlc.CreateUserParams{
			TenantID:     user.TenantID,
			Email:        user.Email,
			PasswordHash: user.PasswordHash,
			Status:       user.Status,
		})
		if err != nil {
			// Convert PostgreSQL unique constraint violation to domain error
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return auth.ErrDuplicateEmail
			}
			return err
		}

		result, err = convertUserToDomain(dbUser)
		return err
	})

	return result, err
}

// GetUser retrieves a user by ID without tenant isolation
// Used for pre-authentication operations (email verification, SSO login)
func (u *UsersDB) GetUser(ctx context.Context, id uuid.UUID) (*auth.User, error) {
	var result *auth.User

	err := u.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbUser, err := q.GetUser(ctx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrUserNotFound
			}
			return err
		}

		result, err = convertUserToDomain(dbUser)
		return err
	})

	return result, err
}

// GetUserByEmail retrieves a user by email without tenant isolation
// Pre-authentication operation: emails are globally unique for password users, but may duplicate for SSO users
func (u *UsersDB) GetUserByEmail(ctx context.Context, email string) (*auth.User, error) {
	var result *auth.User

	err := u.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbUser, err := q.GetUserByEmail(ctx, email)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrUserNotFound
			}
			return err
		}

		result, err = convertUserToDomain(dbUser)
		return err
	})

	return result, err
}

// UpdateUser performs a flexible partial update without tenant isolation
// Used for pre-authentication operations (email verification, password reset)
func (u *UsersDB) UpdateUser(ctx context.Context, params *auth.UpdateUserParams) (*auth.User, error) {
	var result *auth.User

	err := u.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbUser, err := q.UpdateUser(ctx, sqlc.UpdateUserParams{
			ID:           params.ID,
			PasswordHash: params.PasswordHash,
			Status:       params.Status,
		})
		if err != nil {
			return fmt.Errorf("failed to update user: %w", err)
		}

		result, err = convertUserToDomain(dbUser)
		return err
	})

	return result, err
}

// UpdateLastLogin updates a user's last login timestamp with tenant isolation
func (u *UsersDB) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	return u.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		return q.UpdateLastLogin(ctx, id)
	})
}

// DeleteUser deletes a user with tenant isolation
func (u *UsersDB) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return u.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		return q.DeleteUser(ctx, id)
	})
}

// DeleteOldUnverifiedUsers deletes unverified users older than the specified number of days
// Cross-tenant cleanup operation runs via scheduled job, not user request
func (u *UsersDB) DeleteOldUnverifiedUsers(ctx context.Context, days int32) error {
	return u.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		if err := q.DeleteOldUnverifiedUsers(ctx, days); err != nil {
			return fmt.Errorf("failed to delete old unverified users: %w", err)
		}
		return nil
	})
}

// convertUserToDomain converts a sqlc User to a domain User
func convertUserToDomain(dbUser sqlc.User) (*auth.User, error) {
	return &auth.User{
		ID:           dbUser.ID,
		TenantID:     dbUser.TenantID,
		Email:        dbUser.Email,
		PasswordHash: dbUser.PasswordHash,
		Status:       dbUser.Status,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
		LastLoginAt:  dbUser.LastLoginAt,
	}, nil
}
