package events

// Event messages for structured logging - used as the msg field in logs
// These are specific to the Heimdall authentication service

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
	UserRegistered = "user_registered"
	UserCreated    = "user_created"
	TenantCreated  = "tenant_created"
)

// OAuth/OIDC Events
const (
	OAuthLoginSucceeded = "oauth_login_succeeded"
	OAuthLoginFailed    = "oauth_login_failed"
	SSOLoginSucceeded   = "sso_login_succeeded"
	SSOLoginFailed      = "sso_login_failed"
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

// OIDC Provider Events
const (
	OIDCProviderCreated      = "oidc_provider_created"
	OIDCProviderUpdated      = "oidc_provider_updated"
	OIDCProviderDeleted      = "oidc_provider_deleted"
	OIDCProviderUnregistered = "oidc_provider_unregistered"
)

// MFA Events
const (
	MFASetupStarted        = "mfa_setup_started"
	MFASetupRequired       = "mfa_setup_required"
	MFAEnabled             = "mfa_enabled"
	MFADisabled            = "mfa_disabled"
	MFAVerificationSuccess = "mfa_verification_success"
	MFAVerificationFailed  = "mfa_verification_failed"
	BackupCodeUsed         = "backup_code_used"
	BackupCodesRegenerated = "backup_codes_regenerated"
)
