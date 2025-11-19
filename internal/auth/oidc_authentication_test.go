package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

func TestStartSSOLogin_Success(t *testing.T) {
	mockProvider := &mockOIDCProvider{
		authURL: "https://sso.example.com/authorize?state=test&code_challenge=...",
	}
	f := newTestFixture(mockProvider, nil)

	tenantID := uuid.New()
	provider := testProviderConfig(tenantID, "example.com")
	provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

	authURL, err := f.service.StartSSOLogin(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("StartSSOLogin failed: %v", err)
	}
	if authURL == "" {
		t.Error("expected authorization URL, got empty string")
	}

	assertSessionCreated(t, f.sessionDB, &provider.ID, &tenantID, nil)
}

func TestStartSSOLogin_DomainNotConfigured(t *testing.T) {
	f := newTestFixture(nil, nil)

	_, err := f.service.StartSSOLogin(context.Background(), "user@unknown.com")
	if !errors.Is(err, ErrSSONotConfigured) {
		t.Errorf("expected ErrSSONotConfigured, got: %v", err)
	}
}

func TestStartOIDCLogin_Success(t *testing.T) {
	mockProvider := &mockOIDCProvider{
		authURL: "https://accounts.google.com/o/oauth2/v2/auth?state=test&...",
	}
	systemProviders := map[sdk.OIDCProviderType]OIDCProvider{
		sdk.OIDCProviderTypeGoogle: mockProvider,
	}
	f := newTestFixture(nil, systemProviders)

	authURL, err := f.service.StartOIDCLogin(context.Background(), sdk.OIDCProviderTypeGoogle)
	if err != nil {
		t.Fatalf("StartOIDCLogin failed: %v", err)
	}
	if authURL == "" {
		t.Error("expected authorization URL, got empty string")
	}

	providerType := sdk.OIDCProviderTypeGoogle
	assertSessionCreated(t, f.sessionDB, nil, nil, &providerType)
}

func TestStartOIDCLogin_ProviderNotConfigured(t *testing.T) {
	f := newTestFixture(nil, nil)

	_, err := f.service.StartOIDCLogin(context.Background(), sdk.OIDCProviderTypeGoogle)
	if !errors.Is(err, ErrOIDCProviderNotConfigured) {
		t.Errorf("expected ErrOIDCProviderNotConfigured, got: %v", err)
	}
}

func TestHandleOIDCCallback_SSONewUser_AutoProvision(t *testing.T) {
	tenantID := uuid.New()

	mockProvider := &mockOIDCProvider{
		tokens:   testTokens(),
		userInfo: testUserInfo("newuser@example.com", "provider-user-123"),
	}
	f := newTestFixture(mockProvider, nil)

	// Setup: create provider and session
	provider := testProviderConfig(tenantID, "example.com")
	provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

	session := testSession(tenantID, provider.ID)
	f.sessionDB.CreateOIDCSession(context.Background(), session)

	// Execute callback
	user, link, err := f.service.HandleOIDCCallback(context.Background(), session.State, "auth-code")
	if err != nil {
		t.Fatalf("HandleOIDCCallback failed: %v", err)
	}
	if user == nil {
		t.Fatal("expected user to be created")
	}

	assertUserMatch(t, user, "newuser@example.com", tenantID, UserStatusActive)
	assertLinkCreated(t, link, "provider-user-123", user.ID)
}

func TestHandleOIDCCallback_SSOExistingUser(t *testing.T) {
	tenantID := uuid.New()

	mockProvider := &mockOIDCProvider{
		tokens:   testTokens(),
		userInfo: testUserInfo("existing@example.com", "provider-user-123"),
	}
	f := newTestFixture(mockProvider, nil)

	// Setup: create provider, existing user, and link
	provider := testProviderConfig(tenantID, "example.com")
	provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

	existingUser := testUser(tenantID, "existing@example.com")
	existingUser, _ = f.userDB.CreateUser(context.Background(), existingUser)

	existingLink := &OIDCLink{
		UserID:         existingUser.ID,
		OIDCProviderID: provider.ID,
		ProviderUserID: "provider-user-123",
		ProviderEmail:  "existing@example.com",
	}
	f.linkDB.CreateOIDCLink(context.Background(), existingLink)

	session := testSession(tenantID, provider.ID)
	f.sessionDB.CreateOIDCSession(context.Background(), session)

	// Execute callback
	user, link, err := f.service.HandleOIDCCallback(context.Background(), session.State, "auth-code")
	if err != nil {
		t.Fatalf("HandleOIDCCallback failed: %v", err)
	}

	// Should return existing user and link
	if user.ID != existingUser.ID {
		t.Error("should return existing user")
	}
	if link.ID != existingLink.ID {
		t.Error("should return existing link")
	}
}

func TestHandleOIDCCallback_AutoProvisioningDisabled(t *testing.T) {
	tenantID := uuid.New()

	mockProvider := &mockOIDCProvider{
		tokens:   testTokens(),
		userInfo: testUserInfo("newuser@example.com", "provider-user-123"),
	}
	f := newTestFixture(mockProvider, nil)

	// Setup: create provider with auto-provisioning disabled
	provider := testProviderConfig(tenantID, "example.com")
	provider.AutoCreateUsers = false // Disabled!
	provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

	session := testSession(tenantID, provider.ID)
	f.sessionDB.CreateOIDCSession(context.Background(), session)

	// Execute callback - should fail because auto-provisioning is disabled
	_, _, err := f.service.HandleOIDCCallback(context.Background(), session.State, "auth-code")
	if !errors.Is(err, ErrAutoProvisioningDisabled) {
		t.Errorf("expected ErrAutoProvisioningDisabled, got: %v", err)
	}
}

func TestHandleOIDCCallback_EmailReassignment_Blocked(t *testing.T) {
	// Test scenario: Old employee leaves company, email reassigned to new employee
	// System should block login when email exists but provider sub is different
	tenantID := uuid.New()

	// New employee has SAME email but DIFFERENT provider sub
	mockProvider := &mockOIDCProvider{
		tokens:   testTokens(),
		userInfo: testUserInfo("employee@example.com", "new-provider-sub-456"),
	}
	f := newTestFixture(mockProvider, nil)

	// Setup: create provider
	provider := testProviderConfig(tenantID, "example.com")
	provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

	// Create old employee's account with OIDC link
	oldEmployee := testUser(tenantID, "employee@example.com")
	oldEmployee, _ = f.userDB.CreateUser(context.Background(), oldEmployee)

	oldLink := &OIDCLink{
		UserID:         oldEmployee.ID,
		OIDCProviderID: provider.ID,
		ProviderUserID: "old-provider-sub-123", // Old employee's provider sub
		ProviderEmail:  "employee@example.com",
	}
	f.linkDB.CreateOIDCLink(context.Background(), oldLink)

	session := testSession(tenantID, provider.ID)
	f.sessionDB.CreateOIDCSession(context.Background(), session)

	// New employee tries to login - should be blocked
	_, _, err := f.service.HandleOIDCCallback(context.Background(), session.State, "auth-code")
	if !errors.Is(err, ErrEmailConflict) {
		t.Errorf("expected ErrEmailConflict for email reassignment, got: %v", err)
	}

	// Verify old account still exists and new account was NOT created
	if len(f.userDB.users) != 1 {
		t.Errorf("expected 1 user (old employee), got %d", len(f.userDB.users))
	}
}

func TestHandleOIDCCallback_EmailReassignment_AllowedAfterDeactivation(t *testing.T) {
	// Test scenario: Admin deactivates old employee, then new employee can login
	tenantID := uuid.New()

	mockProvider := &mockOIDCProvider{
		tokens:   testTokens(),
		userInfo: testUserInfo("employee@example.com", "new-provider-sub-456"),
	}
	f := newTestFixture(mockProvider, nil)

	// Setup: create provider
	provider := testProviderConfig(tenantID, "example.com")
	provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

	// Create old employee's account with OIDC link
	oldEmployee := testUser(tenantID, "employee@example.com")
	oldEmployee, _ = f.userDB.CreateUser(context.Background(), oldEmployee)

	oldLink := &OIDCLink{
		UserID:         oldEmployee.ID,
		OIDCProviderID: provider.ID,
		ProviderUserID: "old-provider-sub-123",
		ProviderEmail:  "employee@example.com",
	}
	f.linkDB.CreateOIDCLink(context.Background(), oldLink)

	// Admin deletes old employee's account (simulating offboarding)
	f.userDB.DeleteUser(context.Background(), oldEmployee.ID)
	f.linkDB.DeleteOIDCLink(context.Background(), oldEmployee.ID, provider.ID)

	session := testSession(tenantID, provider.ID)
	f.sessionDB.CreateOIDCSession(context.Background(), session)

	// New employee login should succeed now
	user, link, err := f.service.HandleOIDCCallback(context.Background(), session.State, "auth-code")
	if err != nil {
		t.Fatalf("HandleOIDCCallback should succeed after old account deleted: %v", err)
	}
	if user == nil {
		t.Fatal("expected new user to be created")
	}
	if link == nil {
		t.Fatal("expected OIDC link to be created")
	}

	// Verify new user is different from old employee
	if user.Email != "employee@example.com" {
		t.Errorf("expected email employee@example.com, got %s", user.Email)
	}
	if user.ID == oldEmployee.ID {
		t.Error("new user should have different ID than old employee")
	}
	if link.ProviderUserID != "new-provider-sub-456" {
		t.Errorf("expected new provider sub, got %s", link.ProviderUserID)
	}
	if link.UserID == oldEmployee.ID {
		t.Error("link should reference new user, not old employee")
	}
}

func TestHandleOIDCCallback_EmailReassignment_SameSubDifferentEmail(t *testing.T) {
	// Test scenario: Provider updates user's email (same sub, different email)
	// System should handle this gracefully since we track by immutable sub claim
	tenantID := uuid.New()

	// User logs in with SAME provider sub but DIFFERENT email (email changed at provider)
	mockProvider := &mockOIDCProvider{
		tokens:   testTokens(),
		userInfo: testUserInfo("newemail@example.com", "provider-sub-123"),
	}
	f := newTestFixture(mockProvider, nil)

	// Setup: create provider
	provider := testProviderConfig(tenantID, "example.com")
	provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

	// Create user with old email
	user := testUser(tenantID, "oldemail@example.com")
	user, _ = f.userDB.CreateUser(context.Background(), user)

	// Link with provider sub
	link := &OIDCLink{
		UserID:         user.ID,
		OIDCProviderID: provider.ID,
		ProviderUserID: "provider-sub-123",
		ProviderEmail:  "oldemail@example.com",
	}
	f.linkDB.CreateOIDCLink(context.Background(), link)

	session := testSession(tenantID, provider.ID)
	f.sessionDB.CreateOIDCSession(context.Background(), session)

	// Should succeed - we track by sub, not email
	returnedUser, returnedLink, err := f.service.HandleOIDCCallback(context.Background(), session.State, "auth-code")
	if err != nil {
		t.Fatalf("HandleOIDCCallback should succeed for same sub with different email: %v", err)
	}

	// Should return existing user and link (tracked by immutable sub)
	if returnedUser.ID != user.ID {
		t.Error("should return existing user")
	}
	if returnedLink.ID != link.ID {
		t.Error("should return existing link")
	}
}

func TestHandleOIDCCallback_EmailNotVerified(t *testing.T) {
	tenantID := uuid.New()

	mockProvider := &mockOIDCProvider{
		tokens: testTokens(),
		userInfo: &OIDCUserInfo{
			Sub:           "provider-user-123",
			Email:         "newuser@example.com",
			EmailVerified: false, // Not verified!
			Name:          "New User",
		},
		claims: &OIDCClaims{
			EmailVerified: false,
		},
	}
	f := newTestFixture(mockProvider, nil)

	// Setup: create provider with email verification required
	provider := testProviderConfig(tenantID, "example.com")
	provider.RequireEmailVerification = true
	provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

	session := testSession(tenantID, provider.ID)
	f.sessionDB.CreateOIDCSession(context.Background(), session)

	// Should fail because email is not verified
	_, _, err := f.service.HandleOIDCCallback(context.Background(), session.State, "auth-code")
	if !errors.Is(err, ErrProviderEmailNotVerified) {
		t.Errorf("expected ErrProviderEmailNotVerified, got: %v", err)
	}
}

// OAuth Flow Error Cases

func TestHandleOIDCCallback_TokenExchangeFailed(t *testing.T) {
	tenantID := uuid.New()

	// Mock provider returns error during token exchange
	mockProvider := &mockOIDCProvider{
		tokensError: errors.New("token exchange failed"),
	}
	f := newTestFixture(mockProvider, nil)

	provider := testProviderConfig(tenantID, "example.com")
	provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

	session := testSession(tenantID, provider.ID)
	f.sessionDB.CreateOIDCSession(context.Background(), session)

	// Should fail when token exchange fails
	_, _, err := f.service.HandleOIDCCallback(context.Background(), session.State, "auth-code")
	if err == nil {
		t.Error("expected error when token exchange fails")
	}
}

func TestHandleOIDCCallback_UserInfoFetchFailed(t *testing.T) {
	tenantID := uuid.New()

	// Token exchange succeeds but userinfo fetch fails
	mockProvider := &mockOIDCProvider{
		tokens:        testTokens(),
		userInfoError: errors.New("userinfo endpoint failed"),
	}
	f := newTestFixture(mockProvider, nil)

	provider := testProviderConfig(tenantID, "example.com")
	provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

	session := testSession(tenantID, provider.ID)
	f.sessionDB.CreateOIDCSession(context.Background(), session)

	// Should fail when userinfo fetch fails
	_, _, err := f.service.HandleOIDCCallback(context.Background(), session.State, "auth-code")
	if err == nil {
		t.Error("expected error when userinfo fetch fails")
	}
}

// Session Security Tests

func TestHandleOIDCCallback_InvalidState(t *testing.T) {
	f := newTestFixture(nil, nil)

	// Attempt callback with state that doesn't exist
	_, _, err := f.service.HandleOIDCCallback(context.Background(), "invalid-state", "auth-code")
	if !errors.Is(err, ErrOIDCSessionNotFound) {
		t.Errorf("expected ErrOIDCSessionNotFound for invalid state, got: %v", err)
	}
}

func TestHandleOIDCCallback_ExpiredSession(t *testing.T) {
	tenantID := uuid.New()
	f := newTestFixture(nil, nil)

	provider := testProviderConfig(tenantID, "example.com")
	provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

	// Create expired session
	session := testSession(tenantID, provider.ID)
	session.ExpiresAt = time.Now().Add(-1 * time.Hour) // Expired 1 hour ago
	f.sessionDB.CreateOIDCSession(context.Background(), session)

	// Should fail for expired session
	_, _, err := f.service.HandleOIDCCallback(context.Background(), session.State, "auth-code")
	if !errors.Is(err, ErrOIDCSessionNotFound) {
		t.Errorf("expected ErrOIDCSessionNotFound for expired session, got: %v", err)
	}
}

func TestStartOIDCLogin_GeneratesUniqueState(t *testing.T) {
	mockProvider := &mockOIDCProvider{
		authURL: "https://accounts.google.com/o/oauth2/v2/auth",
	}

	systemProviders := map[sdk.OIDCProviderType]OIDCProvider{
		sdk.OIDCProviderTypeGoogle: mockProvider,
	}
	f := newTestFixture(nil, systemProviders)

	// Generate multiple sessions
	states := make(map[string]bool)
	for i := 0; i < 5; i++ {
		_, err := f.service.StartOIDCLogin(context.Background(), sdk.OIDCProviderTypeGoogle)
		if err != nil {
			t.Fatalf("StartOIDCLogin failed: %v", err)
		}
	}

	// Verify all states are unique
	for state := range f.sessionDB.sessions {
		if states[state] {
			t.Errorf("duplicate state token generated: %s", state)
		}
		states[state] = true
	}

	if len(states) != 5 {
		t.Errorf("expected 5 unique states, got %d", len(states))
	}
}

// Individual OAuth Flow Tests

func TestHandleOIDCCallback_IndividualOAuth_NewUser(t *testing.T) {
	mockProvider := &mockOIDCProvider{
		tokens:   testTokens(),
		userInfo: testUserInfo("newuser@gmail.com", "google-user-123"),
	}

	systemProviders := map[sdk.OIDCProviderType]OIDCProvider{
		sdk.OIDCProviderTypeGoogle: mockProvider,
	}
	f := newTestFixture(nil, systemProviders)

	session := testIndividualOAuthSession(sdk.OIDCProviderTypeGoogle)
	f.sessionDB.CreateOIDCSession(context.Background(), session)

	user, _, err := f.service.HandleOIDCCallback(context.Background(), session.State, "auth-code")
	if err != nil {
		t.Fatalf("HandleOIDCCallback failed: %v", err)
	}
	if user == nil {
		t.Fatal("expected user to be created")
	}

	// Verify user created with correct details and own tenant
	if user.Email != "newuser@gmail.com" {
		t.Errorf("expected email newuser@gmail.com, got %s", user.Email)
	}
	if user.Status != UserStatusActive {
		t.Errorf("expected user status active, got %s", user.Status)
	}
	if user.TenantID == uuid.Nil {
		t.Error("user should have a tenant ID")
	}
}

func TestHandleOIDCCallback_IndividualOAuth_ExistingUser(t *testing.T) {
	mockProvider := &mockOIDCProvider{
		tokens:   testTokens(),
		userInfo: testUserInfo("existing@gmail.com", "google-user-123"),
	}

	systemProviders := map[sdk.OIDCProviderType]OIDCProvider{
		sdk.OIDCProviderTypeGoogle: mockProvider,
	}
	f := newTestFixture(nil, systemProviders)

	// Create existing user
	existingUser := testUser(uuid.New(), "existing@gmail.com")
	existingUser, _ = f.userDB.CreateUser(context.Background(), existingUser)

	session := testIndividualOAuthSession(sdk.OIDCProviderTypeGoogle)
	f.sessionDB.CreateOIDCSession(context.Background(), session)

	user, _, err := f.service.HandleOIDCCallback(context.Background(), session.State, "auth-code")
	if err != nil {
		t.Fatalf("HandleOIDCCallback failed: %v", err)
	}

	if user.ID != existingUser.ID {
		t.Error("should return existing user")
	}
}

func TestHandleOIDCCallback_IndividualOAuth_EmailNotVerified(t *testing.T) {
	mockProvider := &mockOIDCProvider{
		tokens: testTokens(),
		userInfo: &OIDCUserInfo{
			Sub:           "google-user-123",
			Email:         "unverified@gmail.com",
			EmailVerified: false,
			Name:          "Unverified User",
		},
		claims: &OIDCClaims{EmailVerified: false},
	}
	systemProviders := map[sdk.OIDCProviderType]OIDCProvider{
		sdk.OIDCProviderTypeGoogle: mockProvider,
	}
	f := newTestFixture(nil, systemProviders)

	session := testIndividualOAuthSession(sdk.OIDCProviderTypeGoogle)
	f.sessionDB.CreateOIDCSession(context.Background(), session)

	_, _, err := f.service.HandleOIDCCallback(context.Background(), session.State, "auth-code")
	if !errors.Is(err, ErrProviderEmailNotVerified) {
		t.Errorf("expected ErrProviderEmailNotVerified, got: %v", err)
	}
}

// Missing Required Claims Tests

func TestHandleOIDCCallback_MissingSubClaim(t *testing.T) {
	mockProvider := &mockOIDCProvider{
		tokens: testTokens(),
		userInfo: &OIDCUserInfo{
			Sub:           "",
			Email:         "user@example.com",
			EmailVerified: true,
			Name:          "User",
		},
	}
	f := newTestFixture(mockProvider, nil)

	tenantID := uuid.New()
	provider := testProviderConfig(tenantID, "example.com")
	provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

	session := testSession(tenantID, provider.ID)
	f.sessionDB.CreateOIDCSession(context.Background(), session)

	_, _, err := f.service.HandleOIDCCallback(context.Background(), session.State, "auth-code")
	if err == nil {
		t.Error("expected error when sub claim is missing")
	}
}

func TestHandleOIDCCallback_MissingEmailClaim(t *testing.T) {
	mockProvider := &mockOIDCProvider{
		tokens: testTokens(),
		userInfo: &OIDCUserInfo{
			Sub:           "provider-user-123",
			Email:         "",
			EmailVerified: true,
			Name:          "User",
		},
	}
	f := newTestFixture(mockProvider, nil)

	tenantID := uuid.New()
	provider := testProviderConfig(tenantID, "example.com")
	provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

	session := testSession(tenantID, provider.ID)
	f.sessionDB.CreateOIDCSession(context.Background(), session)

	_, _, err := f.service.HandleOIDCCallback(context.Background(), session.State, "auth-code")
	if err == nil {
		t.Error("expected error when email claim is missing")
	}
}

// OIDC Provider CRUD Tests

func TestStartSSOLogin_ProviderFromDifferentTenant(t *testing.T) {
	// Domain-based SSO discovery doesn't have tenant isolation
	// Domains are globally unique across all tenants
	mockProvider := &mockOIDCProvider{authURL: "https://sso1.example.com/auth"}
	f := newTestFixture(mockProvider, nil)

	tenant1 := uuid.New()
	provider := testProviderConfig(tenant1, "example.com")
	f.providerDB.CreateOIDCProvider(context.Background(), provider)

	authURL, err := f.service.StartSSOLogin(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("StartSSOLogin failed: %v", err)
	}
	if authURL == "" {
		t.Error("should generate auth URL")
	}
}

func TestHandleOIDCCallback_CreateUserInCorrectTenant(t *testing.T) {
	mockProvider := &mockOIDCProvider{
		tokens:   testTokens(),
		userInfo: testUserInfo("user@example.com", "sub-123"),
	}
	f := newTestFixture(mockProvider, nil)

	tenant1 := uuid.New()
	provider := testProviderConfig(tenant1, "example.com")
	provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

	session := testSession(tenant1, provider.ID)
	f.sessionDB.CreateOIDCSession(context.Background(), session)

	user, _, err := f.service.HandleOIDCCallback(context.Background(), session.State, "code")
	if err != nil {
		t.Fatalf("HandleOIDCCallback failed: %v", err)
	}
	if user.TenantID != tenant1 {
		t.Errorf("user should be in tenant1, got %s", user.TenantID)
	}
}
