package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

const registrationTokenExpiration = 24 * time.Hour

// userDB defines the interface for user database operations
type userDB interface {
	CreateUser(ctx context.Context, user *User) (*User, error)
	GetUser(ctx context.Context, id uuid.UUID) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, params *UpdateUserParams) (*User, error)
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
}

type tenantsDB interface {
	CreateTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error)
}

type hasher interface {
	HashPassword(password string) (string, error)
	VerifyPassword(password string, encodedHash string) error
}

type oidcService interface {
	IsSSORequired(ctx context.Context, email string) (bool, error)
}

type emailClient interface {
	SendVerificationEmail(ctx context.Context, email, token string) error
	SendPasswordResetEmail(ctx context.Context, email, token string) error
}

type tokenDB interface {
	CreateToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*UserToken, error)
	GetToken(ctx context.Context, token string) (*UserToken, error)
	DeleteToken(ctx context.Context, userID uuid.UUID) error
}

type loginAttemptsService interface {
	RecordFailedLogin(ctx context.Context, email string, userID *uuid.UUID, ipAddress string, lastLoginAt *time.Time) error
	RecordSuccessfulLogin(ctx context.Context, email string, userID *uuid.UUID, ipAddress string) error
	IsAccountLocked(ctx context.Context, email string) (bool, time.Time, error)
}

type rbacService interface {
	GetUserScopes(ctx context.Context, userID uuid.UUID) ([]sdk.Scope, error)
	SetupSystemAdminRole(ctx context.Context, userID uuid.UUID) error
	SetUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error
}

// UserServiceConfig holds the dependencies for creating a UserService
type UserServiceConfig struct {
	UserDB               userDB
	TenantsDB            tenantsDB
	Hasher               hasher
	EmailClient          emailClient
	VerificationTokenDB  tokenDB
	PasswordResetTokenDB tokenDB
	LoginAttemptsService loginAttemptsService
	OIDCService          oidcService
	RBACService          rbacService
	Logger               logger
}

// UserService handles user registration, login, email verification, and password management
type UserService struct {
	userDB               userDB
	tenantsDB            tenantsDB
	hasher               hasher
	emailClient          emailClient
	verificationTokenDB  tokenDB
	passwordResetTokenDB tokenDB
	loginAttemptsService loginAttemptsService
	oidcService          oidcService
	rbacService          rbacService
	logger               logger
}

func NewUserService(config *UserServiceConfig) *UserService {
	return &UserService{
		userDB:               config.UserDB,
		tenantsDB:            config.TenantsDB,
		hasher:               config.Hasher,
		emailClient:          config.EmailClient,
		verificationTokenDB:  config.VerificationTokenDB,
		passwordResetTokenDB: config.PasswordResetTokenDB,
		oidcService:          config.OIDCService,
		loginAttemptsService: config.LoginAttemptsService,
		rbacService:          config.RBACService,
		logger:               config.Logger,
	}
}
