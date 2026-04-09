// Package events defines structured log message constants for heimdall.
package events

// Authentication Events
const (
	LoginSucceeded         = "login_succeeded"
	PasswordResetRequested = "password_reset_requested"
	PasswordResetCompleted = "password_reset_completed"
	PasswordChanged        = "password_changed"
	EmailVerified          = "email_verified"
	AccountLocked          = "account_locked"
)

// User Management Events
const (
	TenantCreated  = "tenant_created"
	UserRegistered = "user_registered"
	UserCreated    = "user_created"
)

// RBAC Events
const (
	RoleCreated            = "role_created"
	RoleUpdated            = "role_updated"
	RoleDeleted            = "role_deleted"
	RolePermissionsUpdated = "role_permissions_updated"
	UserRolesUpdated       = "user_roles_updated"
	UserPermissionsUpdated = "user_permissions_updated"
)

// OAuth/OIDC Events
const (
	OAuthLoginFailed         = "oauth_login_failed"
	SSOLoginFailed           = "sso_login_failed"
	OIDCProviderCreated      = "oidc_provider_created"
	OIDCProviderUpdated      = "oidc_provider_updated"
	OIDCProviderDeleted      = "oidc_provider_deleted"
	OIDCProviderUnregistered = "oidc_provider_unregistered"
)

// MFA Events
const (
	MFASetupStarted        = "mfa_setup_started"
	MFAEnabled             = "mfa_enabled"
	MFADisabled            = "mfa_disabled"
	MFASetupRequired       = "mfa_setup_required"
	MFAVerificationSuccess = "mfa_verification_success"
	MFAVerificationFailed  = "mfa_verification_failed"
	BackupCodeUsed         = "backup_code_used"
	BackupCodesRegenerated = "backup_codes_regenerated"
)

// Session Events
const (
	SessionCreated          = "session_created"
	SessionRevoked          = "session_revoked"
	AllSessionsRevoked      = "all_sessions_revoked"
	ExpiredSessionsDeleted  = "expired_sessions_deleted"
	SessionValidationFailed = "session_validation_failed"
	TokenReuseDetected      = "token_reuse_detected"
)

// Trusted Device Events
const (
	TrustedDeviceCreated    = "trusted_device_created"
	TrustedDeviceAllRevoked = "trusted_device_all_revoked"
	MFASkippedTrustedDevice = "mfa_skipped_trusted_device"
)
