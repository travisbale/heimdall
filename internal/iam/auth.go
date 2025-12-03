package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/events"
	"github.com/travisbale/knowhere/crypto/token"
	"github.com/travisbale/knowhere/identity"
)

type passwordService interface {
	VerifyCredentials(ctx context.Context, email, password string) (*User, error)
}

type oidcAuthService interface {
	ProcessCallback(ctx context.Context, state, code string) (*User, error)
}

type userAccountService interface {
	VerifyEmailAndSetPassword(ctx context.Context, tokenStr, password string) (*User, error)
}

type mfaVerificationService interface {
	IsMFAEnabled(ctx context.Context, userID uuid.UUID) (bool, error)
	VerifyCode(ctx context.Context, userID uuid.UUID, code string) error
	SetupMFA(ctx context.Context, userID uuid.UUID) (*MFAEnrollment, error)
	EnableMFA(ctx context.Context, userID uuid.UUID, code string) error
}

type jwtService interface {
	IssueAccessToken(tenantID, userID uuid.UUID, scopes []Scope) (string, time.Duration, error)
	IssueMFAChallengeToken(tenantID, userID uuid.UUID) (string, time.Duration, error)
	IssueMFASetupToken(tenantID, userID uuid.UUID) (string, time.Duration, error)
	IssueRefreshToken(tenantID, userID uuid.UUID) (string, time.Duration, error)
	ValidateMFAChallengeToken(token string) (*JWTClaims, error)
	ValidateMFASetupToken(token string) (*JWTClaims, error)
	ValidateToken(token string) (*JWTClaims, error)
}

type sessionStorageService interface {
	StoreSession(ctx context.Context, rt *RefreshToken) error
	ValidateSession(ctx context.Context, refreshToken string) (*RefreshToken, error)
	RotateSession(ctx context.Context, refreshToken string) (*RefreshToken, error)
	RevokeSessionByToken(ctx context.Context, refreshToken string) error
	RevokeAllSessions(ctx context.Context, userID uuid.UUID) error
}

type trustedDeviceService interface {
	CreateTrustedDevice(ctx context.Context, device *TrustedDevice) (string, error)
	ValidateTrustedDevice(ctx context.Context, deviceToken string, userID uuid.UUID, ipAddress string) (bool, error)
	RevokeAllTrustedDevices(ctx context.Context, userID uuid.UUID) error
}

type passwordChangeService interface {
	ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error
}

// AuthService orchestrates authentication flows
type AuthService struct {
	PasswordService       passwordService
	PasswordChangeService passwordChangeService
	OIDCService           oidcAuthService
	UserService           userAccountService
	MFAService            mfaVerificationService
	RBACService           rbacService
	JWTService            jwtService
	SessionService        sessionStorageService
	TrustedDeviceService  trustedDeviceService
	Logger                logger
}

// ============================================================================
// Authentication - Primary login flows
// ============================================================================

// AuthenticateWithPassword handles password-based authentication
func (s *AuthService) AuthenticateWithPassword(ctx context.Context, email, password, deviceToken string) (*SessionTokens, error) {
	user, err := s.PasswordService.VerifyCredentials(ctx, email, password)
	if err != nil {
		return nil, err
	}

	// deviceToken is optional - if provided and valid, MFA may be skipped for trusted devices
	return s.completeAuthentication(ctx, user, deviceToken)
}

// AuthenticateWithOIDC handles OAuth/OIDC callback
func (s *AuthService) AuthenticateWithOIDC(ctx context.Context, state, code string) (*SessionTokens, error) {
	user, err := s.OIDCService.ProcessCallback(ctx, state, code)
	if err != nil {
		return nil, err
	}

	// OIDC logins don't support trusted device token (no cookie available in redirect)
	return s.completeAuthentication(ctx, user, "")
}

// CompleteRegistration handles email verification and auto-login
func (s *AuthService) CompleteRegistration(ctx context.Context, token, password string) (*SessionTokens, error) {
	user, err := s.UserService.VerifyEmailAndSetPassword(ctx, token, password)
	if err != nil {
		return nil, err
	}

	// New registrations don't have trusted devices yet
	return s.completeAuthentication(ctx, user, "")
}

// AuthenticateWithMFA completes MFA challenge and issues final tokens
func (s *AuthService) AuthenticateWithMFA(ctx context.Context, challengeToken, code string, trustDevice bool) (*SessionTokens, error) {
	claims, err := s.JWTService.ValidateMFAChallengeToken(challengeToken)
	if err != nil {
		return nil, ErrInvalidChallengeToken
	}

	// Set tenant context from token for RLS-protected operations
	ctx = identity.WithActor(ctx, claims.TenantID, claims.UserID)

	if err := s.MFAService.VerifyCode(ctx, claims.UserID, code); err != nil {
		return nil, err
	}

	tokens, err := s.createSession(ctx, claims.TenantID, claims.UserID)
	if err != nil {
		return nil, err
	}

	// Create trusted device token if requested
	if trustDevice && s.TrustedDeviceService != nil {
		device := &TrustedDevice{
			UserID:    claims.UserID,
			TenantID:  claims.TenantID,
			UserAgent: identity.GetUserAgent(ctx),
			IPAddress: identity.GetIPAddress(ctx),
		}
		deviceToken, err := s.TrustedDeviceService.CreateTrustedDevice(ctx, device)
		if err != nil {
			s.Logger.ErrorContext(ctx, "failed to create trusted device", "error", err)
			// Don't fail the request, just skip setting the device token
		} else {
			tokens.DeviceToken = deviceToken
		}
	}

	return tokens, nil
}

// ============================================================================
// MFA Setup - Required MFA enrollment flow
// ============================================================================

// SetupRequiredMFA validates the setup token and initiates MFA enrollment
func (s *AuthService) SetupRequiredMFA(ctx context.Context, setupToken string) (*MFAEnrollment, error) {
	claims, err := s.JWTService.ValidateMFASetupToken(setupToken)
	if err != nil {
		return nil, ErrInvalidSetupToken
	}

	// Set tenant context from token for RLS-protected operations
	ctx = identity.WithActor(ctx, claims.TenantID, claims.UserID)

	return s.MFAService.SetupMFA(ctx, claims.UserID)
}

// EnableRequiredMFA validates the setup token, enables MFA, and returns a challenge token
func (s *AuthService) EnableRequiredMFA(ctx context.Context, setupToken, code string) (*SessionTokens, error) {
	claims, err := s.JWTService.ValidateMFASetupToken(setupToken)
	if err != nil {
		return nil, ErrInvalidSetupToken
	}

	// Set tenant context from token for RLS-protected operations
	ctx = identity.WithActor(ctx, claims.TenantID, claims.UserID)

	if err := s.MFAService.EnableMFA(ctx, claims.UserID, code); err != nil {
		return nil, err
	}

	s.Logger.InfoContext(ctx, events.MFAEnabled, "required", true)

	return s.issueMFAChallenge(claims.TenantID, claims.UserID)
}

// ============================================================================
// Session Management - Refresh, logout, and session control
// ============================================================================

// RefreshSession validates a refresh token, rotates it, and generates new session tokens.
// Token rotation: old token is revoked, new token is issued with same family_id.
// If a revoked token is reused, it's detected as theft and entire family is revoked.
func (s *AuthService) RefreshSession(ctx context.Context, refreshToken string) (*SessionTokens, error) {
	claims, err := s.JWTService.ValidateToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired refresh token: %w", err)
	}

	// Set tenant context from token for RLS-protected operations
	ctx = identity.WithActor(ctx, claims.TenantID, claims.UserID)

	oldSession, err := s.SessionService.RotateSession(ctx, refreshToken)
	if err != nil {
		if err == ErrTokenReused {
			s.HandleTokenReuse(ctx, claims.UserID)
		}
		s.Logger.InfoContext(ctx, events.SessionValidationFailed, "error", err)
		return nil, ErrSessionRevoked
	}

	// Create new session with same family_id (continues the token chain)
	return s.createSessionFamily(ctx, oldSession.FamilyID, claims.TenantID, claims.UserID)
}

// Logout revokes the session associated with the given refresh token
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	// Validate token to get tenant context for RLS
	claims, err := s.JWTService.ValidateToken(refreshToken)
	if err != nil {
		return fmt.Errorf("invalid refresh token: %w", err)
	}

	ctx = identity.WithActor(ctx, claims.TenantID, claims.UserID)
	return s.SessionService.RevokeSessionByToken(ctx, refreshToken)
}

// SignOutEverywhere revokes all sessions and trusted devices for a user
func (s *AuthService) SignOutEverywhere(ctx context.Context, userID uuid.UUID) error {
	// Revoke all sessions
	if err := s.SessionService.RevokeAllSessions(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke sessions: %w", err)
	}

	// Revoke all trusted devices
	if s.TrustedDeviceService != nil {
		if err := s.TrustedDeviceService.RevokeAllTrustedDevices(ctx, userID); err != nil {
			s.Logger.ErrorContext(ctx, "failed to revoke trusted devices",
				"user_id", userID,
				"error", err)
			// Don't fail - sessions are already revoked
		}
	}

	s.Logger.InfoContext(ctx, events.AllSessionsRevoked, "user_id", userID)
	return nil
}

// ============================================================================
// Account Security - Password changes, token reuse, trusted devices
// ============================================================================

// ChangePassword orchestrates password change with security side effects.
// Revokes all trusted devices after password change.
func (s *AuthService) ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	if err := s.PasswordChangeService.ChangePassword(ctx, userID, oldPassword, newPassword); err != nil {
		return err
	}

	// Revoke all trusted devices (security measure)
	if s.TrustedDeviceService != nil {
		if err := s.TrustedDeviceService.RevokeAllTrustedDevices(ctx, userID); err != nil {
			s.Logger.ErrorContext(ctx, "failed to revoke trusted devices on password change",
				"user_id", userID,
				"error", err)
			// Don't fail the request - password was already changed
		}
	}

	return nil
}

// HandleTokenReuse handles a detected token reuse attempt (potential theft).
// Revokes all trusted devices for the user as a security measure.
func (s *AuthService) HandleTokenReuse(ctx context.Context, userID uuid.UUID) {
	// Revoke all trusted devices (potential security breach)
	if s.TrustedDeviceService != nil {
		if err := s.TrustedDeviceService.RevokeAllTrustedDevices(ctx, userID); err != nil {
			s.Logger.ErrorContext(ctx, "failed to revoke trusted devices on token reuse",
				"user_id", userID,
				"error", err)
		}
	}
}

// ============================================================================
// Private helpers - Authentication flow internals
// ============================================================================

// completeAuthentication checks MFA status and either issues tokens or requires MFA
func (s *AuthService) completeAuthentication(ctx context.Context, user *User, deviceToken string) (*SessionTokens, error) {
	// Set tenant context for RLS-protected operations
	ctx = identity.WithActor(ctx, user.TenantID, user.ID)

	mfaEnabled, err := s.MFAService.IsMFAEnabled(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check MFA status: %w", err)
	}

	if mfaEnabled {
		// Check for trusted device before requiring MFA
		if deviceToken != "" && s.TrustedDeviceService != nil {
			ipAddress := identity.GetIPAddress(ctx)
			trusted, err := s.TrustedDeviceService.ValidateTrustedDevice(ctx, deviceToken, user.ID, ipAddress)
			if err == nil && trusted {
				s.Logger.InfoContext(ctx, events.MFASkippedTrustedDevice)
				return s.createSession(ctx, user.TenantID, user.ID)
			}
		}

		return s.issueMFAChallenge(user.TenantID, user.ID)
	}

	// Check if role requires MFA but user hasn't set it up
	rolesRequireMFA, err := s.RBACService.UserRolesRequireMFA(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check MFA requirements: %w", err)
	}

	if rolesRequireMFA {
		s.Logger.InfoContext(ctx, events.MFASetupRequired)
		return s.issueMFASetupChallenge(user.TenantID, user.ID)
	}

	return s.createSession(ctx, user.TenantID, user.ID)
}

// issueMFAChallenge creates a challenge token for MFA verification
func (s *AuthService) issueMFAChallenge(tenantID, userID uuid.UUID) (*SessionTokens, error) {
	challengeToken, expiration, err := s.JWTService.IssueMFAChallengeToken(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate MFA challenge token: %w", err)
	}

	return &SessionTokens{
		MFAChallengeToken:      challengeToken,
		MFAChallengeExpiration: expiration,
	}, nil
}

// issueMFASetupChallenge creates a setup token for required MFA configuration
func (s *AuthService) issueMFASetupChallenge(tenantID, userID uuid.UUID) (*SessionTokens, error) {
	setupToken, expiration, err := s.JWTService.IssueMFASetupToken(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate MFA setup token: %w", err)
	}

	return &SessionTokens{
		MFASetupToken:      setupToken,
		MFASetupExpiration: expiration,
	}, nil
}

// createSession issues access and refresh tokens for a fully authenticated user (new login)
func (s *AuthService) createSession(ctx context.Context, tenantID, userID uuid.UUID) (*SessionTokens, error) {
	// New login starts a new token family
	return s.createSessionFamily(ctx, uuid.New(), tenantID, userID)
}

// createSessionFamily issues tokens with a specific family_id (for token rotation)
func (s *AuthService) createSessionFamily(ctx context.Context, familyID, tenantID, userID uuid.UUID) (*SessionTokens, error) {
	scopes, err := s.RBACService.GetUserScopes(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user scopes: %w", err)
	}

	accessToken, accessExpiration, err := s.JWTService.IssueAccessToken(tenantID, userID, scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, refreshExpiration, err := s.JWTService.IssueRefreshToken(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	rt := &RefreshToken{
		UserID:    userID,
		TenantID:  tenantID,
		TokenHash: token.Hash(refreshToken),
		FamilyID:  familyID,
		UserAgent: identity.GetUserAgent(ctx),
		IPAddress: identity.GetIPAddress(ctx),
		ExpiresAt: time.Now().Add(refreshExpiration),
	}

	// Store session in database for tracking and revocation
	if err := s.SessionService.StoreSession(ctx, rt); err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	// Log successful authentication - user is now fully authenticated
	s.Logger.AuditContext(ctx, events.LoginSucceeded)

	return &SessionTokens{
		AccessToken:       accessToken,
		RefreshToken:      refreshToken,
		AccessExpiration:  accessExpiration,
		RefreshExpiration: refreshExpiration,
	}, nil
}
