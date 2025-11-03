package auth

import (
	"database/sql/driver"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// UserStatus represents the status of a user
type UserStatus string

const (
	UserStatusUnverified UserStatus = "unverified"
	UserStatusActive     UserStatus = "active"
	UserStatusSuspended  UserStatus = "suspended"
	UserStatusInactive   UserStatus = "inactive"
)

// Scan implements the sql.Scanner interface
func (s *UserStatus) Scan(value any) error {
	if value == nil {
		return fmt.Errorf("cannot scan nil into UserStatus")
	}
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("cannot scan %T into UserStatus", value)
	}
	*s = UserStatus(str)
	return nil
}

// Value implements the driver.Valuer interface
func (s UserStatus) Value() (driver.Value, error) {
	return string(s), nil
}

// TenantStatus represents the status of a tenant
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusInactive  TenantStatus = "inactive"
)

// Scan implements the sql.Scanner interface
func (s *TenantStatus) Scan(value any) error {
	if value == nil {
		return fmt.Errorf("cannot scan nil into TenantStatus")
	}
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("cannot scan %T into TenantStatus", value)
	}
	*s = TenantStatus(str)
	return nil
}

// Value implements the driver.Valuer interface
func (s TenantStatus) Value() (driver.Value, error) {
	return string(s), nil
}

// User represents a user in the system
type User struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	Email        string
	PasswordHash string
	Status       UserStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastLoginAt  *time.Time
}

// Tenant represents a tenant in the system
type Tenant struct {
	ID        uuid.UUID
	Name      string
	Status    TenantStatus
	CreatedAt time.Time
	UpdatedAt time.Time
}

// VerificationToken represents an email verification token
type VerificationToken struct {
	UserID    uuid.UUID
	Token     string
	ExpiresAt time.Time
	CreatedAt time.Time
}
