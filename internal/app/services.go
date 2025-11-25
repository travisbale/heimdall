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
	password      *auth.PasswordService
	mfa           *auth.MFAService
	oidc          *auth.OIDCService
	rbac          *auth.RBACService
	loginAttempts *auth.LoginAttemptsService
	session       *auth.SessionService
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
		Issuer:                      config.JWTIssuer,
		PrivateKeyPath:              config.JWTPrivateKeyPath,
		PublicKeyPath:               config.JWTPublicKeyPath,
		AccessTokenExpiration:       15 * time.Minute,
		RefreshTokenExpiration:      config.JWTExpiration,
		MFAChallengeTokenExpiration: 5 * time.Minute,
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

	// Session service for token generation
	sessionService := auth.NewSessionService(&auth.SessionServiceConfig{
		MFASettingsDB: dbs.mfaSettings,
		RBACService:   rbacService,
		JWTService:    jwtService,
		Logger:        clog.New("session_service"),
	})

	// OIDC service for OAuth/SSO authentication
	oidcService := auth.NewOIDCService(&auth.OIDCServiceConfig{
		OIDCProviderDB:     dbs.oidcProviders,
		OIDCLinkDB:         dbs.oidcLinks,
		OIDCSessionDB:      dbs.oidcSessions,
		UserDB:             dbs.users,
		TenantsDB:          dbs.tenants,
		RBACService:        rbacService,
		SessionService:     sessionService,
		SystemProviders:    systemProviders,
		RegistrationClient: oidc.NewRegistrationClient(),
		ProviderFactory:    oidc.NewProviderFactory(),
		PublicURL:          config.PublicURL,
		Logger:             clog.New("oidc_service"),
	})

	// Password service for password authentication
	passwordService := auth.NewPasswordService(&auth.PasswordServiceConfig{
		UserDB:               dbs.users,
		Hasher:               passwordHasher,
		PasswordResetTokenDB: dbs.passwordResetTokens,
		EmailClient:          emailClient,
		LoginAttemptsService: loginAttemptsService,
		SessionService:       sessionService,
		Logger:               clog.New("password_service"),
	})

	// User service for registration and user management
	userService := auth.NewUserService(&auth.UserServiceConfig{
		UserDB:              dbs.users,
		TenantsDB:           dbs.tenants,
		Hasher:              passwordHasher,
		EmailClient:         emailClient,
		VerificationTokenDB: dbs.verificationTokens,
		OIDCService:         oidcService,
		RBACService:         rbacService,
		SessionService:      sessionService,
		Logger:              clog.New("user_service"),
	})

	// MFA service for TOTP and backup codes
	mfaService := auth.NewMFAService(&auth.MFAServiceCofig{
		MFASettingsDB:      dbs.mfaSettings,
		BackupCodesDB:      dbs.mfaBackupCodes,
		UsersDB:            dbs.users,
		Verifier:           totp.NewVerifier(dbs.mfaSettings, cipher, config.TOTPPeriod),
		Hasher:             passwordHasher,
		ChallengeValidator: jwtService.Validator,
		SessionService:     sessionService,
		Logger:             clog.New("mfa_service"),
	})

	return &services{
		user:          userService,
		password:      passwordService,
		mfa:           mfaService,
		oidc:          oidcService,
		rbac:          rbacService,
		loginAttempts: loginAttemptsService,
		session:       sessionService,
		jwt:           jwtService,
	}, nil
}
