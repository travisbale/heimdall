package app

import (
	"time"

	"github.com/travisbale/heimdall/clog"
	"github.com/travisbale/heimdall/crypto/aes"
	"github.com/travisbale/heimdall/crypto/argon2"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/email/mailman"
	"github.com/travisbale/heimdall/internal/mfa/totp"
	"github.com/travisbale/heimdall/internal/oidc"
	"github.com/travisbale/heimdall/jwt"
	"github.com/travisbale/heimdall/sdk"
)

// services holds all business logic service instances
type services struct {
	user          *auth.UserService
	mfa           *auth.MFAService
	oidc          *auth.OIDCService
	rbac          *auth.RBACService
	loginAttempts *auth.LoginAttemptsService
	jwt           *jwt.Service
}

// initializeServices creates all business logic service instances
func initializeServices(
	config *Config,
	dbs *databases,
	systemProviders map[sdk.OIDCProviderType]auth.OIDCProvider,
	emailClient *mailman.Client,
	cipher *aes.Cipher,
) (*services, error) {
	// JWT service for token issuance and validation
	jwtConfig := &jwt.Config{
		Issuer:                 config.JWTIssuer,
		PrivateKeyPath:         config.JWTPrivateKeyPath,
		PublicKeyPath:          config.JWTPublicKeyPath,
		AccessTokenExpiration:  15 * time.Minute,
		RefreshTokenExpiration: config.JWTExpiration,
	}

	jwtService, err := jwt.NewService(jwtConfig)
	if err != nil {
		return nil, err
	}

	// Use environment-appropriate Argon2 parameters
	passwordHasher := argon2.NewHasher(getArgon2Config(config.Environment))

	// Login attempts service for account lockout tracking
	loginAttemptsService := auth.NewLoginAttemptsService(dbs.loginAttempts, clog.New("login_attempts_service"))

	// RBAC service for roles and permissions
	rbacService := auth.NewRBACService(&auth.RBACServiceConfig{
		RolesDB:           dbs.roles,
		PermissionsDB:     dbs.permissions,
		RolePermissionsDB: dbs.rolePermissions,
		UserRolesDB:       dbs.userRoles,
		UserPermissionsDB: dbs.userPermissions,
		Logger:            clog.New("rbac_service"),
	})

	// OIDC service for OAuth/SSO authentication
	oidcService := auth.NewOIDCService(&auth.OIDCServiceConfig{
		OIDCProviderDB:     dbs.oidcProviders,
		OIDCLinkDB:         dbs.oidcLinks,
		OIDCSessionDB:      dbs.oidcSessions,
		UserDB:             dbs.users,
		TenantsDB:          dbs.tenants,
		RBACService:        rbacService,
		SystemProviders:    systemProviders,
		RegistrationClient: oidc.NewRegistrationClient(),
		ProviderFactory:    oidc.NewProviderFactory(),
		PublicURL:          config.PublicURL,
		Logger:             clog.New("oidc_service"),
	})

	// User service for authentication and registration
	userService := auth.NewUserService(&auth.UserServiceConfig{
		UserDB:               dbs.users,
		TenantsDB:            dbs.tenants,
		Hasher:               passwordHasher,
		EmailClient:          emailClient,
		VerificationTokenDB:  dbs.verificationTokens,
		PasswordResetTokenDB: dbs.passwordResetTokens,
		LoginAttemptsService: loginAttemptsService,
		OIDCService:          oidcService,
		RBACService:          rbacService,
		Logger:               clog.New("user_service"),
	})

	// MFA service for TOTP and backup codes
	mfaService := auth.NewMFAService(&auth.MFAServiceCofig{
		MFASettingsDB: dbs.mfaSettings,
		BackupCodesDB: dbs.mfaBackupCodes,
		UsersDB:       dbs.users,
		Verifier:      totp.NewVerifier(dbs.mfaSettings, cipher, config.TOTPPeriod),
		Hasher:        passwordHasher,
		Logger:        clog.New("mfa_service"),
	})

	return &services{
		user:          userService,
		mfa:           mfaService,
		oidc:          oidcService,
		rbac:          rbacService,
		loginAttempts: loginAttemptsService,
		jwt:           jwtService,
	}, nil
}
