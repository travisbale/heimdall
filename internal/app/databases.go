package app

import (
	"github.com/travisbale/heimdall/crypto/aes"
	"github.com/travisbale/heimdall/internal/db/postgres"
)

// databases holds all database access layer instances
type databases struct {
	tenants             *postgres.TenantsDB
	users               *postgres.UsersDB
	verificationTokens  *postgres.VerificationTokensDB
	passwordResetTokens *postgres.PasswordResetTokensDB
	loginAttempts       *postgres.LoginAttemptsDB
	oidcProviders       *postgres.OIDCProvidersDB
	oidcLinks           *postgres.OIDCLinksDB
	oidcSessions        *postgres.OIDCSessionsDB
	roles               *postgres.RolesDB
	permissions         *postgres.PermissionsDB
	rolePermissions     *postgres.RolePermissionsDB
	userRoles           *postgres.UserRolesDB
	userPermissions     *postgres.UserPermissionsDB
	mfaSettings         *postgres.MFASettingsDB
	mfaBackupCodes      *postgres.MFABackupCodesDB
	refreshTokens       *postgres.RefreshTokensDB
}

// initializeDatabases creates all database access layer instances
func initializeDatabases(db *postgres.DB, cipher *aes.Cipher) *databases {
	return &databases{
		tenants:             postgres.NewTenantsDB(db),
		users:               postgres.NewUsersDB(db),
		verificationTokens:  postgres.NewVerificationTokensDB(db),
		passwordResetTokens: postgres.NewPasswordResetTokensDB(db),
		loginAttempts:       postgres.NewLoginAttemptsDB(db),
		oidcProviders:       postgres.NewOIDCProvidersDB(db, cipher),
		oidcLinks:           postgres.NewOIDCLinksDB(db),
		oidcSessions:        postgres.NewOIDCSessionsDB(db),
		roles:               postgres.NewRolesDB(db),
		permissions:         postgres.NewPermissionsDB(db),
		rolePermissions:     postgres.NewRolePermissionsDB(db),
		userRoles:           postgres.NewUserRolesDB(db),
		userPermissions:     postgres.NewUserPermissionsDB(db),
		mfaSettings:         postgres.NewMFASettingsDB(db),
		mfaBackupCodes:      postgres.NewMFABackupCodesDB(db),
		refreshTokens:       postgres.NewRefreshTokensDB(db),
	}
}
