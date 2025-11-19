package events

// Event messages for structured logging - used as the msg field in logs
// These are specific to the Heimdall authentication service

// Authentication Events
const (
	LoginSuccess           = "login_success"
	LoginFailure           = "login_failure"
	Logout                 = "logout"
	PasswordResetRequested = "password_reset_requested"
	PasswordResetCompleted = "password_reset_completed"
	EmailVerified          = "email_verified"
	AccountLocked          = "account_locked"
	AccountUnlocked        = "account_unlocked"
)

// User Management Events
const (
	UserRegistered    = "user_registered"
	UserCreated       = "user_created"
	UserUpdated       = "user_updated"
	UserStatusChanged = "user_status_changed"
	UserDeleted       = "user_deleted"
)

// OAuth/OIDC Events
const (
	OAuthFlowStarted   = "oauth_flow_started"
	OAuthFlowCompleted = "oauth_flow_completed"
	OAuthFlowFailed    = "oauth_flow_failed"
	SSOLoginSuccess    = "sso_login_success"
	SSOLoginFailure    = "sso_login_failure"
)

// RBAC Events
const (
	RoleCreated        = "role_created"
	RoleUpdated        = "role_updated"
	RoleDeleted        = "role_deleted"
	UserRolesChanged   = "user_roles_changed"
	PermissionAssigned = "permission_assigned"
	PermissionRevoked  = "permission_revoked"
)

// OIDC Provider Events
const (
	OIDCProviderCreated  = "oidc_provider_created"
	OIDCProviderUpdated  = "oidc_provider_updated"
	OIDCProviderDeleted  = "oidc_provider_deleted"
	OIDCProviderEnabled  = "oidc_provider_enabled"
	OIDCProviderDisabled = "oidc_provider_disabled"
)

// Operational Events
const (
	RequestStarted       = "request_started"
	RequestCompleted     = "request_completed"
	RequestFailed        = "request_failed"
	DatabaseError        = "database_error"
	ExternalServiceError = "external_service_error"
)
