package iam

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// Helper to create a test OIDC service
func newTestOIDCService(
	providerDB *mockOIDCProviderDB,
	linkDB *mockOIDCLinkDB,
	sessionDB *mockOIDCSessionDB,
	userDB *mockUserDB,
	tenantsDB *mockTenantsDB,
	rbacService *mockRBACService,
	factory *mockProviderFactory,
	systemProviders map[sdk.OIDCProviderType]OIDCProvider,
) *OIDCService {
	return NewOIDCService(&OIDCServiceConfig{
		OIDCProviderDB:     providerDB,
		OIDCLinkDB:         linkDB,
		OIDCSessionDB:      sessionDB,
		UserDB:             userDB,
		TenantsDB:          tenantsDB,
		RBACService:        rbacService,
		SystemProviders:    systemProviders,
		RegistrationClient: nil, // Not needed for these tests
		ProviderFactory:    factory,
		PublicURL:          "http://localhost:8080",
		Logger:             &mockLogger{},
	})
}

// Test Helpers

// testFixture holds all mocks needed for OIDC service tests
type testFixture struct {
	providerDB *mockOIDCProviderDB
	linkDB     *mockOIDCLinkDB
	sessionDB  *mockOIDCSessionDB
	userDB     *mockUserDB
	tenantsDB  *mockTenantsDB
	service    *OIDCService
}

// newTestFixture creates a complete test fixture with all mocks
func newTestFixture(mockProvider OIDCProvider, systemProviders map[sdk.OIDCProviderType]OIDCProvider) *testFixture {
	providerDB := newMockOIDCProviderDB()
	linkDB := newMockOIDCLinkDB()
	sessionDB := newMockOIDCSessionDB()
	userDB := newMockUserDB()
	tenantsDB := newMockTenantsDB()
	rbacService := newMockRBACService()

	// Wire up dependencies so BootstrapTenant can properly update shared mocks
	tenantsDB.setDependencies(userDB)

	var factory *mockProviderFactory
	if mockProvider != nil {
		factory = &mockProviderFactory{provider: mockProvider}
	} else {
		factory = &mockProviderFactory{}
	}

	service := newTestOIDCService(providerDB, linkDB, sessionDB, userDB, tenantsDB, rbacService, factory, systemProviders)

	return &testFixture{
		providerDB: providerDB,
		linkDB:     linkDB,
		sessionDB:  sessionDB,
		userDB:     userDB,
		tenantsDB:  tenantsDB,
		service:    service,
	}
}

// testProviderConfig creates an OIDCProviderConfig with sensible defaults
func testProviderConfig(tenantID uuid.UUID, domain string) *OIDCProviderConfig {
	return &OIDCProviderConfig{
		TenantID:                 tenantID,
		ProviderName:             "Test SSO",
		IssuerURL:                "https://sso.example.com",
		ClientID:                 "client-id",
		ClientSecret:             "client-secret",
		Scopes:                   []string{"openid", "email", "profile"},
		Enabled:                  true,
		AllowedDomains:           []string{domain},
		AutoCreateUsers:          true,
		RequireEmailVerification: false,
	}
}

// testSession creates an OIDCSession with sensible defaults
func testSession(tenantID uuid.UUID, providerID uuid.UUID) *OIDCSession {
	return &OIDCSession{
		State:          "test-state",
		CodeVerifier:   "test-verifier",
		OIDCProviderID: &providerID,
		TenantID:       &tenantID,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
}

// testUserInfo creates OIDCUserInfo with sensible defaults
func testUserInfo(email, sub string) *OIDCUserInfo {
	return &OIDCUserInfo{
		Sub:           sub,
		Email:         email,
		EmailVerified: true,
		Name:          "Test User",
	}
}

// testTokens creates an OIDCTokenResponse with sensible defaults
func testTokens() *OIDCTokenResponse {
	return &OIDCTokenResponse{
		AccessToken: "access-token",
		IDToken:     "id-token",
	}
}

// testUser creates a User with sensible defaults
func testUser(tenantID uuid.UUID, email string) *User {
	return &User{
		TenantID: tenantID,
		Email:    email,
		Status:   UserStatusActive,
	}
}

// testIndividualOAuthSession creates an OIDCSession for individual OAuth (Google, Microsoft, GitHub)
func testIndividualOAuthSession(providerType sdk.OIDCProviderType) *OIDCSession {
	return &OIDCSession{
		State:          "test-state",
		CodeVerifier:   "test-verifier",
		OIDCProviderID: nil,
		ProviderType:   &providerType,
		TenantID:       nil,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
}

// Assertion Helpers

// assertSessionCreated verifies that exactly one session was created with expected properties
func assertSessionCreated(t *testing.T, sessionDB *mockOIDCSessionDB, wantProviderID *uuid.UUID, wantTenantID *uuid.UUID, wantProviderType *sdk.OIDCProviderType) {
	t.Helper()
	if len(sessionDB.sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(sessionDB.sessions))
		return
	}
	for _, session := range sessionDB.sessions {
		if wantProviderID != nil {
			if session.OIDCProviderID == nil {
				t.Error("session should have OIDCProviderID set")
			} else if *session.OIDCProviderID != *wantProviderID {
				t.Errorf("session should reference provider %v, got %v", *wantProviderID, *session.OIDCProviderID)
			}
		}
		if wantTenantID != nil {
			if session.TenantID == nil {
				t.Error("session should have TenantID set")
			} else if *session.TenantID != *wantTenantID {
				t.Errorf("session should reference tenant %v, got %v", *wantTenantID, *session.TenantID)
			}
		}
		if wantProviderType != nil {
			if session.ProviderType == nil {
				t.Error("session should have ProviderType set")
			} else if *session.ProviderType != *wantProviderType {
				t.Errorf("session should have provider type %v, got %v", *wantProviderType, *session.ProviderType)
			}
		}
	}
}

// assertUserMatch verifies user properties match expected values
func assertUserMatch(t *testing.T, user *User, wantEmail string, wantTenantID uuid.UUID, wantStatus UserStatus) {
	t.Helper()
	if user.Email != wantEmail {
		t.Errorf("expected email %s, got %s", wantEmail, user.Email)
	}
	if user.TenantID != wantTenantID {
		t.Errorf("expected tenant %v, got %v", wantTenantID, user.TenantID)
	}
	if user.Status != wantStatus {
		t.Errorf("expected status %s, got %s", wantStatus, user.Status)
	}
}

// assertLinkCreated verifies an OIDC link was created with expected properties
func assertLinkCreated(t *testing.T, link *OIDCLink, wantSub string, wantUserID uuid.UUID) {
	t.Helper()
	if link == nil {
		t.Fatal("expected OIDC link to be created")
	}
	if link.ProviderUserID != wantSub {
		t.Errorf("expected provider user ID %s, got %s", wantSub, link.ProviderUserID)
	}
	if link.UserID != wantUserID {
		t.Errorf("expected user ID %v, got %v", wantUserID, link.UserID)
	}
}
