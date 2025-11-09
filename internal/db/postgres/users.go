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
// For registration: user.TenantID should be set and we don't use tenant context
// For admin user creation: tenant is extracted from context
func (u *UsersDB) CreateUser(ctx context.Context, user *auth.User) (*auth.User, error) {
	var result *auth.User

	// Use WithTransaction for registration (no tenant context needed)
	err := u.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbUser, err := q.CreateUser(ctx, sqlc.CreateUserParams{
			TenantID:     user.TenantID,
			Email:        user.Email,
			PasswordHash: user.PasswordHash,
			Status:       user.Status,
		})
		if err != nil {
			// Check for unique constraint violation (duplicate email)
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

// GetUser retrieves a user by ID with tenant isolation
func (u *UsersDB) GetUser(ctx context.Context, id uuid.UUID) (*auth.User, error) {
	var result *auth.User

	err := u.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		dbUser, err := q.GetUser(ctx, id)
		if err != nil {
			return err
		}

		result, err = convertUserToDomain(dbUser)
		return err
	})

	return result, err
}

// GetUserByEmail retrieves a user by email without tenant isolation
// This is used during login where we don't have tenant context (pre-authentication)
func (u *UsersDB) GetUserByEmail(ctx context.Context, email string) (*auth.User, error) {
	var result *auth.User

	// Note: We don't have tenant context during login (pre-authentication)
	// Email is unique globally, so we can find the user without RLS
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

// UpdateUser updates a user with tenant isolation
func (u *UsersDB) UpdateUser(ctx context.Context, id uuid.UUID, email string, status auth.UserStatus) (*auth.User, error) {
	var result *auth.User

	err := u.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		dbUser, err := q.UpdateUser(ctx, sqlc.UpdateUserParams{
			ID:     id,
			Email:  email,
			Status: status,
		})
		if err != nil {
			return err
		}

		result, err = convertUserToDomain(dbUser)
		return err
	})

	return result, err
}

// UpdateUserPassword updates a user's password with tenant isolation
func (u *UsersDB) UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	return u.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		return q.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{
			ID:           id,
			PasswordHash: passwordHash,
		})
	})
}

// UpdateLastLogin updates a user's last login timestamp with tenant isolation
func (u *UsersDB) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	return u.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		return q.UpdateLastLogin(ctx, id)
	})
}

// UpdateUserStatus updates a user's status without tenant isolation and returns the updated user
// This is used during email verification where we don't have tenant context
func (u *UsersDB) UpdateUserStatus(ctx context.Context, id uuid.UUID, status auth.UserStatus) (*auth.User, error) {
	var result *auth.User

	// Note: We don't have tenant context during verification
	// The userID is sufficient to identify the user uniquely.
	err := u.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbUser, err := q.UpdateUserStatus(ctx, sqlc.UpdateUserStatusParams{
			ID:     id,
			Status: status,
		})
		if err != nil {
			return fmt.Errorf("failed to update user status: %w", err)
		}

		result, err = convertUserToDomain(dbUser)
		return err
	})

	return result, err
}

// UpdatePassword updates a user's password without tenant isolation
// This is used during password reset where we don't have tenant context
func (u *UsersDB) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	// Note: We don't have tenant context during password reset
	// The userID is sufficient to identify the user uniquely.
	return u.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		if err := q.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{
			ID:           id,
			PasswordHash: passwordHash,
		}); err != nil {
			return fmt.Errorf("failed to update password: %w", err)
		}
		return nil
	})
}

// DeleteUser deletes a user with tenant isolation
func (u *UsersDB) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return u.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		return q.DeleteUser(ctx, id)
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
