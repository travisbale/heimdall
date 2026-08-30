package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/travisbale/heimdall/internal/iam"
)

type UsersDB struct {
	db *DB
}

// NewUsersDB creates a new UsersDB instance
func NewUsersDB(db *DB) *UsersDB {
	return &UsersDB{db: db}
}

// CreateUser persists a user in the current tenant context
func (u *UsersDB) CreateUser(ctx context.Context, user *iam.User) (*iam.User, error) {
	var result *iam.User

	err := u.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		dbUser, err := q.CreateUser(ctx, sqlc.CreateUserParams{
			Email:        user.Email,
			PasswordHash: user.PasswordHash,
			Status:       user.Status,
		})
		if err != nil {
			if _, ok := uniqueViolation(err); ok {
				return iam.ErrDuplicateEmail
			}
			return err
		}

		result, err = convertUserToDomain(dbUser)
		return err
	})

	return result, err
}

func (u *UsersDB) GetUser(ctx context.Context, id uuid.UUID) (*iam.User, error) {
	var result *iam.User

	err := u.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbUser, err := q.GetUser(ctx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return iam.ErrUserNotFound
			}
			return err
		}

		result, err = convertUserToDomain(dbUser)
		return err
	})

	return result, err
}

// An active address is unique across every tenant, so whether one is free is a question no
// single tenant's rows can answer. The name carries that: the interface is where a caller
// chooses, and a comment here is not where they are looking.
func (u *UsersDB) ListUsersByEmailAcrossTenants(ctx context.Context, email string) ([]*iam.User, error) {
	var result []*iam.User

	err := u.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		rows, err := q.ListUsersByEmail(ctx, email)
		if err != nil {
			return err
		}

		result = make([]*iam.User, 0, len(rows))
		for _, row := range rows {
			user, err := convertUserToDomain(row)
			if err != nil {
				return err
			}
			result = append(result, user)
		}
		return nil
	})

	return result, err
}

// Unscoped, and named so: login is keyed on an address, which no tenant is known for yet.
// Pre-authentication operation: emails are globally unique for password users, but may duplicate for SSO users
func (u *UsersDB) GetUserByEmailAcrossTenants(ctx context.Context, email string) (*iam.User, error) {
	var result *iam.User

	err := u.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbUser, err := q.GetUserByEmail(ctx, email)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return iam.ErrUserNotFound
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
func (u *UsersDB) UpdateUser(ctx context.Context, params *iam.UpdateUserParams) (*iam.User, error) {
	var result *iam.User

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

func (u *UsersDB) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	return u.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		return q.UpdateLastLogin(ctx, id)
	})
}

func (u *UsersDB) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return u.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		return q.DeleteUser(ctx, id)
	})
}

// DeleteOldUnverifiedUsers deletes unverified users older than the given number of days,
// one tenant at a time because the DELETE policy on users requires a tenant.
func (u *UsersDB) DeleteOldUnverifiedUsers(ctx context.Context, days int32) error {
	return sweepTenants(ctx, u.db, func(ctx context.Context, q *sqlc.Queries) error {
		return q.DeleteOldUnverifiedUsers(ctx, days)
	})
}

// convertUserToDomain converts a sqlc User to a domain User
func convertUserToDomain(dbUser sqlc.User) (*iam.User, error) {
	return &iam.User{
		ID:           dbUser.ID,
		TenantID:     dbUser.TenantID,
		Email:        dbUser.Email,
		PasswordHash: dbUser.PasswordHash,
		FirstName:    dbUser.FirstName,
		LastName:     dbUser.LastName,
		Status:       dbUser.Status,
		LastLoginAt:  dbUser.LastLoginAt,
	}, nil
}
