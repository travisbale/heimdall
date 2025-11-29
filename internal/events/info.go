package events

// Info events are system/operational events logged locally for debugging and monitoring.
// These are not sent to uatu as they're not relevant to end-user audit trails.

// Authentication Info Events
const (
	PasswordResetRequested = "password_reset_requested"
	PasswordResetCompleted = "password_reset_completed"
	PasswordChanged        = "password_changed"
	EmailVerified          = "email_verified"
	AccountLocked          = "account_locked"
)

// User Management Info Events
const (
	TenantCreated  = "tenant_created"
	UserRegistered = "user_registered"
	UserCreated    = "user_created"
)

// OAuth/OIDC Info Events
const (
	OAuthLoginFailed = "oauth_login_failed"
	SSOLoginFailed   = "sso_login_failed"
)

// OIDC Provider Info Events
const (
	OIDCProviderUnregistered = "oidc_provider_unregistered"
)

// MFA Info Events
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

// Session Info Events
const (
	SessionCreated          = "session_created"
	SessionRevoked          = "session_revoked"
	AllSessionsRevoked      = "all_sessions_revoked"
	ExpiredSessionsDeleted  = "expired_sessions_deleted"
	SessionValidationFailed = "session_validation_failed"
	TokenReuseDetected      = "token_reuse_detected"
)

// Trusted Device Info Events
const (
	TrustedDeviceCreated    = "trusted_device_created"
	TrustedDeviceAllRevoked = "trusted_device_all_revoked"
	MFASkippedTrustedDevice = "mfa_skipped_trusted_device"
)
