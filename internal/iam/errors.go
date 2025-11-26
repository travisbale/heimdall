package iam

import "errors"

// Authentication errors
var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrUserNotFound = errors.New("user not found")
var ErrAccountIsInactive = errors.New("user account is not active")
var ErrEmailNotVerified = errors.New("email address not verified")
var ErrDuplicateEmail = errors.New("email address is already registered")
var ErrAccountLocked = errors.New("account is temporarily locked due to too many failed login attempts")
var ErrVerificationTokenNotFound = errors.New("verification token not found or expired")
var ErrPasswordResetTokenNotFound = errors.New("password reset token not found or expired")
var ErrAccountAlreadyVerified = errors.New("account has already been verified")

// OIDC flow errors
var ErrOIDCLinkNotFound = errors.New("oidc link not found")
var ErrOIDCLinkAlreadyExists = errors.New("user already has this provider linked")
var ErrOIDCProviderAccountAlreadyLinked = errors.New("this provider account is already linked to another user")
var ErrOIDCSessionNotFound = errors.New("oidc session not found or expired")
var ErrOIDCProviderNotFound = errors.New("oidc provider not found")
var ErrInvalidOIDCState = errors.New("invalid oidc state parameter")

// OIDC discovery and registration errors
var ErrOIDCDiscoveryFailed = errors.New("failed to discover OIDC provider")
var ErrOIDCIssuerMismatch = errors.New("OIDC issuer mismatch")
var ErrOIDCRegistrationFailed = errors.New("dynamic client registration failed")

// Corporate SSO errors
var ErrSSONotConfigured = errors.New("SSO is not configured for this domain")
var ErrOIDCProviderNotConfigured = errors.New("OAuth provider is not configured")
var ErrSSORequired = errors.New("this email domain requires SSO login")
var ErrAutoProvisioningDisabled = errors.New("automatic user provisioning is not enabled for this domain")
var ErrProviderEmailNotVerified = errors.New("email not verified by OAuth provider")
var ErrEmailConflict = errors.New("email address conflicts with existing account")

// RBAC errors
var ErrRoleNotFound = errors.New("role not found")
var ErrPermissionNotFound = errors.New("permission not found")

// MFA errors
var ErrMFANotEnabled = errors.New("MFA is not enabled for this user")
var ErrMFAAlreadyEnabled = errors.New("MFA is already enabled for this user")
var ErrInvalidMFACode = errors.New("invalid MFA code")
var ErrMFACodeAlreadyUsed = errors.New("MFA code has already been used")
var ErrInvalidBackupCode = errors.New("invalid backup code")
var ErrBackupCodeAlreadyUsed = errors.New("backup code has already been used")
var ErrInvalidChallengeToken = errors.New("invalid or expired challenge token")
var ErrInvalidSetupToken = errors.New("invalid or expired setup token")

// Session management errors
var ErrSessionNotFound = errors.New("session not found or expired")
var ErrSessionRevoked = errors.New("session has been revoked")
var ErrTokenReused = errors.New("refresh token reuse detected")

// Trusted device errors
var ErrTrustedDeviceNotFound = errors.New("trusted device not found or expired")
