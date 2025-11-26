package app

import (
	"log/slog"
	"time"

	"github.com/travisbale/heimdall/crypto/aes"
	"github.com/travisbale/heimdall/crypto/argon2"
	"github.com/travisbale/heimdall/internal/email/mailman"
	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/internal/mfa/totp"
	"github.com/travisbale/heimdall/internal/oidc"
	"github.com/travisbale/heimdall/jwt"
	"github.com/travisbale/heimdall/sdk"
)

// services holds all business logic service instances
type services struct {
	user          *iam.UserService
	password      *iam.PasswordService
	mfa           *iam.MFAService
	oidcAuth      *iam.OIDCAuthService
	oidcProvider  *iam.OIDCProviderService
	rbac          *iam.RBACService
	loginAttempts *iam.LoginAttemptsService
	auth          *iam.AuthService
	session       *iam.SessionService
	trustedDevice *iam.TrustedDeviceService
	jwt           *jwt.Service
}

// initializeServices creates all business logic service instances
func initializeServices(
	config *Config,
	dbs *databases,
	systemProviders map[sdk.OIDCProviderType]iam.OIDCProvider,
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
		MFASetupTokenExpiration:     5 * time.Minute,
	}

	jwtService, err := jwt.NewService(jwtConfig)
	if err != nil {
		return nil, err
	}

	// Use environment-appropriate Argon2 parameters
	passwordHasher := argon2.NewHasher(getArgon2Config(config.Environment))

	// Login attempts service for account lockout tracking
	loginAttemptsService := iam.NewLoginAttemptsService(dbs.loginAttempts, slog.Default())

	// RBAC service for roles and permissions
	rbacService := iam.NewRBACService(&iam.RBACServiceConfig{
		RolesDB:           dbs.roles,
		PermissionsDB:     dbs.permissions,
		RolePermissionsDB: dbs.rolePermissions,
		UserRolesDB:       dbs.userRoles,
		UserPermissionsDB: dbs.userPermissions,
		Logger:            slog.Default(),
	})

	// OIDC provider service for provider CRUD operations
	oidcProviderService := iam.NewOIDCProviderService(&iam.OIDCProviderServiceConfig{
		OIDCProviderDB:     dbs.oidcProviders,
		RegistrationClient: oidc.NewRegistrationClient(),
		ProviderFactory:    oidc.NewProviderFactory(),
		PublicURL:          config.PublicURL,
		Logger:             slog.Default(),
	})

	// OIDC auth service for OAuth/SSO authentication flows
	oidcAuthService := iam.NewOIDCAuthService(&iam.OIDCAuthServiceConfig{
		OIDCProviderService: oidcProviderService,
		OIDCLinkDB:          dbs.oidcLinks,
		OIDCSessionDB:       dbs.oidcSessions,
		UserDB:              dbs.users,
		TenantsDB:           dbs.tenants,
		SystemProviders:     systemProviders,
		ProviderFactory:     oidc.NewProviderFactory(),
		PublicURL:           config.PublicURL,
		Logger:              slog.Default(),
	})

	// Password service for password authentication
	passwordService := iam.NewPasswordService(&iam.PasswordServiceConfig{
		UserDB:               dbs.users,
		Hasher:               passwordHasher,
		PasswordResetTokenDB: dbs.passwordResetTokens,
		EmailClient:          emailClient,
		LoginAttemptsService: loginAttemptsService,
		Logger:               slog.Default(),
	})

	// User service for registration and user management
	userService := iam.NewUserService(&iam.UserServiceConfig{
		UserDB:              dbs.users,
		TenantsDB:           dbs.tenants,
		Hasher:              passwordHasher,
		EmailClient:         emailClient,
		VerificationTokenDB: dbs.verificationTokens,
		OIDCService:         oidcProviderService,
		RBACService:         rbacService,
		Logger:              slog.Default(),
	})

	// MFA service for TOTP and backup codes
	mfaService := iam.NewMFAService(&iam.MFAServiceConfig{
		MFASettingsDB: dbs.mfaSettings,
		BackupCodesDB: dbs.mfaBackupCodes,
		UsersDB:       dbs.users,
		Verifier:      totp.NewVerifier(dbs.mfaSettings, cipher, config.TOTPPeriod),
		Hasher:        passwordHasher,
		Logger:        slog.Default(),
	})

	// Session service for refresh token storage and management
	sessionService := iam.NewSessionService(&iam.SessionServiceConfig{
		RefreshTokenDB: dbs.refreshTokens,
		Logger:         slog.Default(),
	})

	// Trusted device service for MFA bypass on trusted devices
	trustedDeviceService := iam.NewTrustedDeviceService(&iam.TrustedDeviceServiceConfig{
		TrustedDeviceDB: dbs.trustedDevices,
		Logger:          slog.Default(),
	})

	// Auth service orchestrates authentication flows
	authService := iam.NewAuthService(&iam.AuthServiceConfig{
		PasswordService:       passwordService,
		PasswordChangeService: passwordService,
		OIDCService:           oidcAuthService,
		UserService:           userService,
		MFAService:            mfaService,
		RBACService:           rbacService,
		JWTService:            jwtService,
		SessionService:        sessionService,
		TrustedDeviceService:  trustedDeviceService,
		Logger:                slog.Default(),
	})

	return &services{
		user:          userService,
		password:      passwordService,
		mfa:           mfaService,
		oidcAuth:      oidcAuthService,
		oidcProvider:  oidcProviderService,
		rbac:          rbacService,
		loginAttempts: loginAttemptsService,
		auth:          authService,
		session:       sessionService,
		trustedDevice: trustedDeviceService,
		jwt:           jwtService,
	}, nil
}
