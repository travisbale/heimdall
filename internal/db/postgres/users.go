package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/db/postgres/sqlc"
	"github.com/travisbale/heimdall/tenant"
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
		tenantPgID := pgtype.UUID{}
		if err := tenantPgID.Scan(user.TenantID.String()); err != nil {
			return fmt.Errorf("invalid tenant ID: %w", err)
		}

		dbUser, err := q.CreateUser(ctx, sqlc.CreateUserParams{
			TenantID:     tenantPgID,
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
	tenantID, err := tenant.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant from context: %w", err)
	}

	var result *auth.User

	err = u.db.WithTenantContext(ctx, tenantID, func(q *sqlc.Queries) error {
		userPgID := pgtype.UUID{}
		if err := userPgID.Scan(id.String()); err != nil {
			return fmt.Errorf("invalid user ID: %w", err)
		}

		dbUser, err := q.GetUser(ctx, userPgID)
		if err != nil {
			return err
		}

		result, err = convertUserToDomain(dbUser)
		return err
	})

	return result, err
}

// GetUserByEmail retrieves a user by email with tenant isolation
func (u *UsersDB) GetUserByEmail(ctx context.Context, email string) (*auth.User, error) {
	tenantID, err := tenant.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant from context: %w", err)
	}

	var result *auth.User

	err = u.db.WithTenantContext(ctx, tenantID, func(q *sqlc.Queries) error {
		dbUser, err := q.GetUserByEmail(ctx, email)
		if err != nil {
			return err
		}

		result, err = convertUserToDomain(dbUser)
		return err
	})

	return result, err
}

// UpdateUser updates a user with tenant isolation
func (u *UsersDB) UpdateUser(ctx context.Context, id uuid.UUID, email string, status auth.UserStatus) (*auth.User, error) {
	tenantID, err := tenant.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant from context: %w", err)
	}

	var result *auth.User

	err = u.db.WithTenantContext(ctx, tenantID, func(q *sqlc.Queries) error {
		userPgID := pgtype.UUID{}
		if err := userPgID.Scan(id.String()); err != nil {
			return fmt.Errorf("invalid user ID: %w", err)
		}

		dbUser, err := q.UpdateUser(ctx, sqlc.UpdateUserParams{
			ID:     userPgID,
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
	tenantID, err := tenant.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tenant from context: %w", err)
	}

	return u.db.WithTenantContext(ctx, tenantID, func(q *sqlc.Queries) error {
		userPgID := pgtype.UUID{}
		if err := userPgID.Scan(id.String()); err != nil {
			return fmt.Errorf("invalid user ID: %w", err)
		}

		return q.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{
			ID:           userPgID,
			PasswordHash: passwordHash,
		})
	})
}

// UpdateLastLogin updates a user's last login timestamp with tenant isolation
func (u *UsersDB) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	tenantID, err := tenant.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tenant from context: %w", err)
	}

	return u.db.WithTenantContext(ctx, tenantID, func(q *sqlc.Queries) error {
		userPgID := pgtype.UUID{}
		if err := userPgID.Scan(id.String()); err != nil {
			return fmt.Errorf("invalid user ID: %w", err)
		}

		return q.UpdateLastLogin(ctx, userPgID)
	})
}

// UpdateUserStatus updates a user's status without tenant isolation
// This is used during email verification where we don't have tenant context
func (u *UsersDB) UpdateUserStatus(ctx context.Context, id uuid.UUID, status auth.UserStatus) error {
	// Note: We don't have tenant context during verification
	// The userID is sufficient to identify the user uniquely.
	return u.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		userPgID := pgtype.UUID{}
		if err := userPgID.Scan(id.String()); err != nil {
			return fmt.Errorf("invalid user ID: %w", err)
		}

		if err := q.UpdateUserStatus(ctx, sqlc.UpdateUserStatusParams{
			ID:     userPgID,
			Status: status,
		}); err != nil {
			return fmt.Errorf("failed to update user status: %w", err)
		}
		return nil
	})
}

// DeleteUser deletes a user with tenant isolation
func (u *UsersDB) DeleteUser(ctx context.Context, id uuid.UUID) error {
	tenantID, err := tenant.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tenant from context: %w", err)
	}

	return u.db.WithTenantContext(ctx, tenantID, func(q *sqlc.Queries) error {
		userPgID := pgtype.UUID{}
		if err := userPgID.Scan(id.String()); err != nil {
			return fmt.Errorf("invalid user ID: %w", err)
		}

		return q.DeleteUser(ctx, userPgID)
	})
}

// convertUserToDomain converts a sqlc User to a domain User
func convertUserToDomain(dbUser sqlc.User) (*auth.User, error) {
	userID, err := uuid.FromBytes(dbUser.ID.Bytes[:])
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in database: %w", err)
	}

	tenantID, err := uuid.FromBytes(dbUser.TenantID.Bytes[:])
	if err != nil {
		return nil, fmt.Errorf("invalid tenant ID in database: %w", err)
	}

	var createdAt, updatedAt time.Time
	if dbUser.CreatedAt.Valid {
		createdAt = dbUser.CreatedAt.Time
	}
	if dbUser.UpdatedAt.Valid {
		updatedAt = dbUser.UpdatedAt.Time
	}

	var lastLoginAt *time.Time
	if dbUser.LastLoginAt.Valid {
		lastLoginAt = &dbUser.LastLoginAt.Time
	}

	return &auth.User{
		ID:           userID,
		TenantID:     tenantID,
		Email:        dbUser.Email,
		PasswordHash: dbUser.PasswordHash,
		Status:       dbUser.Status,
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
		LastLoginAt:  lastLoginAt,
	}, nil
}
