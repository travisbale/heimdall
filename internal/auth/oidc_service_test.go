package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// Mock implementations for testing

type mockOIDCProviderDB struct {
	providers map[uuid.UUID]*OIDCProviderConfig
	domains   map[string][]*OIDCProviderConfig
}

func newMockOIDCProviderDB() *mockOIDCProviderDB {
	return &mockOIDCProviderDB{
		providers: make(map[uuid.UUID]*OIDCProviderConfig),
		domains:   make(map[string][]*OIDCProviderConfig),
	}
}

func (m *mockOIDCProviderDB) CreateOIDCProvider(ctx context.Context, provider *OIDCProviderConfig) (*OIDCProviderConfig, error) {
	provider.ID = uuid.New()
	provider.CreatedAt = time.Now()
	provider.UpdatedAt = time.Now()
	m.providers[provider.ID] = provider
	for _, domain := range provider.AllowedDomains {
		m.domains[domain] = append(m.domains[domain], provider)
	}
	return provider, nil
}

func (m *mockOIDCProviderDB) GetOIDCProviderByID(ctx context.Context, id uuid.UUID) (*OIDCProviderConfig, error) {
	provider, ok := m.providers[id]
	if !ok {
		return nil, ErrOIDCProviderNotFound
	}
	return provider, nil
}

func (m *mockOIDCProviderDB) GetOIDCProvidersByDomain(ctx context.Context, domain string) ([]*OIDCProviderConfig, error) {
	providers, ok := m.domains[domain]
	if !ok || len(providers) == 0 {
		return nil, nil
	}
	return providers, nil
}

func (m *mockOIDCProviderDB) ListOIDCProviders(ctx context.Context) ([]*OIDCProviderConfig, error) {
	providers := make([]*OIDCProviderConfig, 0, len(m.providers))
	for _, p := range m.providers {
		providers = append(providers, p)
	}
	return providers, nil
}

func (m *mockOIDCProviderDB) UpdateOIDCProvider(ctx context.Context, params *UpdateOIDCProviderParams) (*OIDCProviderConfig, error) {
	provider, ok := m.providers[params.ID]
	if !ok {
		return nil, ErrOIDCProviderNotFound
	}
	if params.ProviderName != nil {
		provider.ProviderName = *params.ProviderName
	}
	if params.Enabled != nil {
		provider.Enabled = *params.Enabled
	}
	provider.UpdatedAt = time.Now()
	return provider, nil
}

func (m *mockOIDCProviderDB) DeleteOIDCProviderByID(ctx context.Context, id uuid.UUID) error {
	if _, ok := m.providers[id]; !ok {
		return ErrOIDCProviderNotFound
	}
	delete(m.providers, id)
	return nil
}

type mockOIDCLinkDB struct {
	links map[string]*OIDCLink // key: providerID+providerUserID
}

func newMockOIDCLinkDB() *mockOIDCLinkDB {
	return &mockOIDCLinkDB{
		links: make(map[string]*OIDCLink),
	}
}

func (m *mockOIDCLinkDB) CreateOIDCLink(ctx context.Context, link *OIDCLink) (*OIDCLink, error) {
	link.ID = uuid.New()
	link.LinkedAt = time.Now()
	key := link.OIDCProviderID.String() + link.ProviderUserID
	m.links[key] = link
	return link, nil
}

func (m *mockOIDCLinkDB) GetOIDCLinkByProvider(ctx context.Context, providerID uuid.UUID, providerUserID string) (*OIDCLink, error) {
	key := providerID.String() + providerUserID
	link, ok := m.links[key]
	if !ok {
		return nil, ErrOIDCLinkNotFound
	}
	return link, nil
}

func (m *mockOIDCLinkDB) GetOIDCLinkByUser(ctx context.Context, userID uuid.UUID, providerID uuid.UUID) (*OIDCLink, error) {
	for _, link := range m.links {
		if link.UserID == userID && link.OIDCProviderID == providerID {
			return link, nil
		}
	}
	return nil, ErrOIDCLinkNotFound
}

func (m *mockOIDCLinkDB) ListOIDCLinksByUser(ctx context.Context, userID uuid.UUID) ([]*OIDCLink, error) {
	links := make([]*OIDCLink, 0)
	for _, link := range m.links {
		if link.UserID == userID {
			links = append(links, link)
		}
	}
	return links, nil
}

func (m *mockOIDCLinkDB) UpdateOIDCLinkLastUsed(ctx context.Context, id uuid.UUID) error {
	for _, link := range m.links {
		if link.ID == id {
			now := time.Now()
			link.LastUsedAt = &now
			return nil
		}
	}
	return ErrOIDCLinkNotFound
}

func (m *mockOIDCLinkDB) DeleteOIDCLink(ctx context.Context, userID uuid.UUID, providerID uuid.UUID) error {
	for key, link := range m.links {
		if link.UserID == userID && link.OIDCProviderID == providerID {
			delete(m.links, key)
			return nil
		}
	}
	return ErrOIDCLinkNotFound
}

type mockOIDCSessionDB struct {
	sessions map[string]*OIDCSession // key: state
}

func newMockOIDCSessionDB() *mockOIDCSessionDB {
	return &mockOIDCSessionDB{
		sessions: make(map[string]*OIDCSession),
	}
}

func (m *mockOIDCSessionDB) CreateOIDCSession(ctx context.Context, session *OIDCSession) (*OIDCSession, error) {
	session.ID = uuid.New()
	session.CreatedAt = time.Now()
	m.sessions[session.State] = session
	return session, nil
}

func (m *mockOIDCSessionDB) GetOIDCSessionByState(ctx context.Context, state string) (*OIDCSession, error) {
	session, ok := m.sessions[state]
	if !ok {
		return nil, ErrOIDCSessionNotFound
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, ErrOIDCSessionNotFound
	}
	return session, nil
}

func (m *mockOIDCSessionDB) DeleteOIDCSession(ctx context.Context, id uuid.UUID) error {
	for state, session := range m.sessions {
		if session.ID == id {
			delete(m.sessions, state)
			return nil
		}
	}
	return ErrOIDCSessionNotFound
}

func (m *mockOIDCSessionDB) DeleteExpiredOIDCSessions(ctx context.Context) error {
	now := time.Now()
	for state, session := range m.sessions {
		if now.After(session.ExpiresAt) {
			delete(m.sessions, state)
		}
	}
	return nil
}

type mockUserDB struct {
	users  map[uuid.UUID]*User
	emails map[string]*User
}

func newMockUserDB() *mockUserDB {
	return &mockUserDB{
		users:  make(map[uuid.UUID]*User),
		emails: make(map[string]*User),
	}
}

func (m *mockUserDB) CreateUser(ctx context.Context, user *User) (*User, error) {
	user.ID = uuid.New()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	m.users[user.ID] = user
	m.emails[user.Email] = user
	return user, nil
}

func (m *mockUserDB) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	user, ok := m.users[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (m *mockUserDB) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	user, ok := m.emails[email]
	if !ok {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (m *mockUserDB) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
	return m.GetUserByID(ctx, id)
}

func (m *mockUserDB) UpdateUser(ctx context.Context, params *UpdateUserParams) (*User, error) {
	user, ok := m.users[params.ID]
	if !ok {
		return nil, ErrUserNotFound
	}
	if params.PasswordHash != nil {
		user.PasswordHash = *params.PasswordHash
	}
	if params.Status != nil {
		user.Status = *params.Status
	}
	user.UpdatedAt = time.Now()
	return user, nil
}

func (m *mockUserDB) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	user, ok := m.users[id]
	if !ok {
		return ErrUserNotFound
	}
	now := time.Now()
	user.LastLoginAt = &now
	return nil
}

func (m *mockUserDB) DeleteUser(ctx context.Context, id uuid.UUID) error {
	user, ok := m.users[id]
	if !ok {
		return ErrUserNotFound
	}
	delete(m.users, id)
	delete(m.emails, user.Email)
	return nil
}

type mockOIDCProvider struct {
	authURL       string
	authURLError  error
	tokens        *OIDCTokenResponse
	tokensError   error
	userInfo      *OIDCUserInfo
	userInfoError error
	claims        *OIDCClaims
	claimsError   error
}

func (m *mockOIDCProvider) GetAuthorizationURL(state, codeVerifier, redirectURI string) (string, error) {
	if m.authURLError != nil {
		return "", m.authURLError
	}
	return m.authURL, nil
}

func (m *mockOIDCProvider) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*OIDCTokenResponse, error) {
	if m.tokensError != nil {
		return nil, m.tokensError
	}
	return m.tokens, nil
}

func (m *mockOIDCProvider) GetUserInfo(ctx context.Context, accessToken string) (*OIDCUserInfo, error) {
	if m.userInfoError != nil {
		return nil, m.userInfoError
	}
	if m.userInfo == nil {
		return nil, fmt.Errorf("no user info configured")
	}
	if err := m.userInfo.Validate(); err != nil {
		return nil, err
	}
	return m.userInfo, nil
}

func (m *mockOIDCProvider) ValidateIDToken(ctx context.Context, idToken string) (*OIDCClaims, error) {
	if m.claimsError != nil {
		return nil, m.claimsError
	}
	if m.claims == nil {
		return nil, errors.New("no claims configured")
	}
	return m.claims, nil
}

type mockProviderFactory struct {
	provider OIDCProvider
	err      error
}

func (m *mockProviderFactory) NewProvider(ctx context.Context, issuerURL, clientID, clientSecret string, scopes []string) (OIDCProvider, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.provider, nil
}

type mockLogger struct{}

func (m *mockLogger) Info(msg string, args ...any)  {}
func (m *mockLogger) Warn(msg string, args ...any)  {}
func (m *mockLogger) Error(msg string, args ...any) {}
func (m *mockLogger) With(args ...any) logger       { return m }

// Helper to create a test OIDC service
func newTestOIDCService(
	providerDB *mockOIDCProviderDB,
	linkDB *mockOIDCLinkDB,
	sessionDB *mockOIDCSessionDB,
	userDB *mockUserDB,
	factory *mockProviderFactory,
	systemProviders map[sdk.OIDCProviderType]OIDCProvider,
) *OIDCService {
	return NewOIDCService(&OIDCServiceConfig{
		OIDCProviderDB:     providerDB,
		OIDCLinkDB:         linkDB,
		OIDCSessionDB:      sessionDB,
		UserDB:             userDB,
		SystemProviders:    systemProviders,
		RegistrationClient: nil, // Not needed for these tests
		ProviderFactory:    factory,
		PublicURL:          "http://localhost:8080",
		Logger:             &mockLogger{},
	})
}

// Tests

func TestStartSSOLogin_Success(t *testing.T) {
	providerDB := newMockOIDCProviderDB()
	sessionDB := newMockOIDCSessionDB()

	// Create a test provider for example.com domain
	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:        tenantID,
		ProviderName:    "Example Corp SSO",
		IssuerURL:       "https://sso.example.com",
		ClientID:        "client-id",
		ClientSecret:    "client-secret",
		Scopes:          []string{"openid", "email", "profile"},
		Enabled:         true,
		AllowedDomains:  []string{"example.com"},
		AutoCreateUsers: true,
	}
	_, err := providerDB.CreateOIDCProvider(context.Background(), provider)
	if err != nil {
		t.Fatalf("failed to create test provider: %v", err)
	}

	mockProvider := &mockOIDCProvider{
		authURL: "https://sso.example.com/authorize?state=test&code_challenge=...",
	}

	factory := &mockProviderFactory{provider: mockProvider}

	service := newTestOIDCService(
		providerDB,
		newMockOIDCLinkDB(),
		sessionDB,
		newMockUserDB(),
		factory,
		nil,
	)

	// Start SSO login for user@example.com
	authURL, err := service.StartSSOLogin(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("StartSSOLogin failed: %v", err)
	}

	if authURL == "" {
		t.Error("expected authorization URL, got empty string")
	}

	// Verify session was created
	if len(sessionDB.sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(sessionDB.sessions))
	}

	for _, session := range sessionDB.sessions {
		if session.OIDCProviderID == nil || *session.OIDCProviderID != provider.ID {
			t.Error("session should reference the provider")
		}
		if session.TenantID == nil || *session.TenantID != tenantID {
			t.Error("session should reference the tenant")
		}
	}
}

func TestStartSSOLogin_DomainNotConfigured(t *testing.T) {
	service := newTestOIDCService(
		newMockOIDCProviderDB(),
		newMockOIDCLinkDB(),
		newMockOIDCSessionDB(),
		newMockUserDB(),
		&mockProviderFactory{},
		nil,
	)

	_, err := service.StartSSOLogin(context.Background(), "user@unknown.com")
	if !errors.Is(err, ErrSSONotConfigured) {
		t.Errorf("expected ErrSSONotConfigured, got: %v", err)
	}
}

func TestStartOIDCLogin_Success(t *testing.T) {
	sessionDB := newMockOIDCSessionDB()

	mockProvider := &mockOIDCProvider{
		authURL: "https://accounts.google.com/o/oauth2/v2/auth?state=test&...",
	}

	systemProviders := map[sdk.OIDCProviderType]OIDCProvider{
		sdk.OIDCProviderTypeGoogle: mockProvider,
	}

	service := newTestOIDCService(
		newMockOIDCProviderDB(),
		newMockOIDCLinkDB(),
		sessionDB,
		newMockUserDB(),
		&mockProviderFactory{},
		systemProviders,
	)

	authURL, err := service.StartOIDCLogin(context.Background(), sdk.OIDCProviderTypeGoogle)
	if err != nil {
		t.Fatalf("StartOIDCLogin failed: %v", err)
	}

	if authURL == "" {
		t.Error("expected authorization URL, got empty string")
	}

	// Verify session was created
	if len(sessionDB.sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(sessionDB.sessions))
	}

	for _, session := range sessionDB.sessions {
		if session.ProviderType == nil || *session.ProviderType != sdk.OIDCProviderTypeGoogle {
			t.Error("session should reference Google provider type")
		}
		if session.OIDCProviderID != nil {
			t.Error("session should not reference a provider ID for system providers")
		}
	}
}

func TestStartOIDCLogin_ProviderNotConfigured(t *testing.T) {
	service := newTestOIDCService(
		newMockOIDCProviderDB(),
		newMockOIDCLinkDB(),
		newMockOIDCSessionDB(),
		newMockUserDB(),
		&mockProviderFactory{},
		make(map[sdk.OIDCProviderType]OIDCProvider), // Empty system providers
	)

	_, err := service.StartOIDCLogin(context.Background(), sdk.OIDCProviderTypeGoogle)
	if !errors.Is(err, ErrOIDCProviderNotConfigured) {
		t.Errorf("expected ErrOIDCProviderNotConfigured, got: %v", err)
	}
}

func TestHandleOIDCCallback_SSONewUser_AutoProvision(t *testing.T) {
	providerDB := newMockOIDCProviderDB()
	linkDB := newMockOIDCLinkDB()
	sessionDB := newMockOIDCSessionDB()
	userDB := newMockUserDB()

	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:                 tenantID,
		ProviderName:             "Example Corp SSO",
		IssuerURL:                "https://sso.example.com",
		ClientID:                 "client-id",
		ClientSecret:             "client-secret",
		Scopes:                   []string{"openid", "email", "profile"},
		Enabled:                  true,
		AllowedDomains:           []string{"example.com"},
		AutoCreateUsers:          true,
		RequireEmailVerification: false,
	}
	provider, _ = providerDB.CreateOIDCProvider(context.Background(), provider)

	// Create session
	state := "test-state"
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   "test-verifier",
		OIDCProviderID: &provider.ID,
		TenantID:       &tenantID,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	sessionDB.CreateOIDCSession(context.Background(), session)

	mockProvider := &mockOIDCProvider{
		tokens: &OIDCTokenResponse{
			AccessToken: "access-token",
			IDToken:     "id-token",
		},
		userInfo: &OIDCUserInfo{
			Sub:           "provider-user-123",
			Email:         "newuser@example.com",
			EmailVerified: true,
			Name:          "New User",
		},
	}

	factory := &mockProviderFactory{provider: mockProvider}

	service := newTestOIDCService(providerDB, linkDB, sessionDB, userDB, factory, nil)

	user, link, err := service.HandleOIDCCallback(context.Background(), state, "auth-code")
	if err != nil {
		t.Fatalf("HandleOIDCCallback failed: %v", err)
	}

	if user == nil {
		t.Fatal("expected user to be created")
	}
	if user.Email != "newuser@example.com" {
		t.Errorf("expected email newuser@example.com, got %s", user.Email)
	}
	if user.TenantID != tenantID {
		t.Error("user should be in the same tenant as the provider")
	}
	if user.Status != UserStatusActive {
		t.Errorf("expected user status active, got %s", user.Status)
	}

	if link == nil {
		t.Fatal("expected OIDC link to be created")
	}
	if link.ProviderUserID != "provider-user-123" {
		t.Errorf("expected provider user ID provider-user-123, got %s", link.ProviderUserID)
	}
}

func TestHandleOIDCCallback_SSOExistingUser(t *testing.T) {
	providerDB := newMockOIDCProviderDB()
	linkDB := newMockOIDCLinkDB()
	sessionDB := newMockOIDCSessionDB()
	userDB := newMockUserDB()

	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:                 tenantID,
		ProviderName:             "Example Corp SSO",
		IssuerURL:                "https://sso.example.com",
		ClientID:                 "client-id",
		ClientSecret:             "client-secret",
		Scopes:                   []string{"openid", "email", "profile"},
		Enabled:                  true,
		AllowedDomains:           []string{"example.com"},
		AutoCreateUsers:          true,
		RequireEmailVerification: false,
	}
	provider, _ = providerDB.CreateOIDCProvider(context.Background(), provider)

	// Create existing user and link
	existingUser := &User{
		TenantID: tenantID,
		Email:    "existing@example.com",
		Status:   UserStatusActive,
	}
	existingUser, _ = userDB.CreateUser(context.Background(), existingUser)

	existingLink := &OIDCLink{
		UserID:         existingUser.ID,
		OIDCProviderID: provider.ID,
		ProviderUserID: "provider-user-123",
		ProviderEmail:  "existing@example.com",
	}
	linkDB.CreateOIDCLink(context.Background(), existingLink)

	// Create session
	state := "test-state"
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   "test-verifier",
		OIDCProviderID: &provider.ID,
		TenantID:       &tenantID,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	sessionDB.CreateOIDCSession(context.Background(), session)

	mockProvider := &mockOIDCProvider{
		tokens: &OIDCTokenResponse{
			AccessToken: "access-token",
			IDToken:     "id-token",
		},
		userInfo: &OIDCUserInfo{
			Sub:           "provider-user-123",
			Email:         "existing@example.com",
			EmailVerified: true,
			Name:          "Existing User",
		},
	}

	factory := &mockProviderFactory{provider: mockProvider}

	service := newTestOIDCService(providerDB, linkDB, sessionDB, userDB, factory, nil)

	user, link, err := service.HandleOIDCCallback(context.Background(), state, "auth-code")
	if err != nil {
		t.Fatalf("HandleOIDCCallback failed: %v", err)
	}

	if user.ID != existingUser.ID {
		t.Error("should return existing user")
	}
	if link.ID != existingLink.ID {
		t.Error("should return existing link")
	}
}

func TestHandleOIDCCallback_AutoProvisioningDisabled(t *testing.T) {
	providerDB := newMockOIDCProviderDB()
	sessionDB := newMockOIDCSessionDB()

	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:                 tenantID,
		ProviderName:             "Example Corp SSO",
		IssuerURL:                "https://sso.example.com",
		ClientID:                 "client-id",
		ClientSecret:             "client-secret",
		Scopes:                   []string{"openid", "email", "profile"},
		Enabled:                  true,
		AllowedDomains:           []string{"example.com"},
		AutoCreateUsers:          false, // Disabled!
		RequireEmailVerification: false,
	}
	provider, _ = providerDB.CreateOIDCProvider(context.Background(), provider)

	// Create session
	state := "test-state"
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   "test-verifier",
		OIDCProviderID: &provider.ID,
		TenantID:       &tenantID,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	sessionDB.CreateOIDCSession(context.Background(), session)

	mockProvider := &mockOIDCProvider{
		tokens: &OIDCTokenResponse{
			AccessToken: "access-token",
			IDToken:     "id-token",
		},
		userInfo: &OIDCUserInfo{
			Sub:           "provider-user-123",
			Email:         "newuser@example.com",
			EmailVerified: true,
			Name:          "New User",
		},
	}

	factory := &mockProviderFactory{provider: mockProvider}

	service := newTestOIDCService(
		providerDB,
		newMockOIDCLinkDB(),
		sessionDB,
		newMockUserDB(),
		factory,
		nil,
	)

	_, _, err := service.HandleOIDCCallback(context.Background(), state, "auth-code")
	if !errors.Is(err, ErrAutoProvisioningDisabled) {
		t.Errorf("expected ErrAutoProvisioningDisabled, got: %v", err)
	}
}

func TestHandleOIDCCallback_EmailReassignment_Blocked(t *testing.T) {
	// Test scenario: Old employee leaves company, email reassigned to new employee
	// System should block login when email exists but provider sub is different
	providerDB := newMockOIDCProviderDB()
	linkDB := newMockOIDCLinkDB()
	sessionDB := newMockOIDCSessionDB()
	userDB := newMockUserDB()

	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:                 tenantID,
		ProviderName:             "Example Corp SSO",
		IssuerURL:                "https://sso.example.com",
		ClientID:                 "client-id",
		ClientSecret:             "client-secret",
		Scopes:                   []string{"openid", "email", "profile"},
		Enabled:                  true,
		AllowedDomains:           []string{"example.com"},
		AutoCreateUsers:          true,
		RequireEmailVerification: false,
	}
	provider, _ = providerDB.CreateOIDCProvider(context.Background(), provider)

	// Create old employee's account with OIDC link
	oldEmployee := &User{
		TenantID: tenantID,
		Email:    "employee@example.com",
		Status:   UserStatusActive,
	}
	oldEmployee, _ = userDB.CreateUser(context.Background(), oldEmployee)

	oldLink := &OIDCLink{
		UserID:         oldEmployee.ID,
		OIDCProviderID: provider.ID,
		ProviderUserID: "old-provider-sub-123", // Old employee's provider sub
		ProviderEmail:  "employee@example.com",
	}
	linkDB.CreateOIDCLink(context.Background(), oldLink)

	// Create session for new employee login attempt
	state := "test-state"
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   "test-verifier",
		OIDCProviderID: &provider.ID,
		TenantID:       &tenantID,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	sessionDB.CreateOIDCSession(context.Background(), session)

	// New employee has SAME email but DIFFERENT provider sub
	mockProvider := &mockOIDCProvider{
		tokens: &OIDCTokenResponse{
			AccessToken: "access-token",
			IDToken:     "id-token",
		},
		userInfo: &OIDCUserInfo{
			Sub:           "new-provider-sub-456", // Different provider sub!
			Email:         "employee@example.com", // Same email address
			EmailVerified: true,
			Name:          "New Employee",
		},
	}

	factory := &mockProviderFactory{provider: mockProvider}

	service := newTestOIDCService(providerDB, linkDB, sessionDB, userDB, factory, nil)

	// New employee tries to login - should be blocked
	_, _, err := service.HandleOIDCCallback(context.Background(), state, "auth-code")
	if !errors.Is(err, ErrEmailConflict) {
		t.Errorf("expected ErrEmailConflict for email reassignment, got: %v", err)
	}

	// Verify old account still exists and new account was NOT created
	users := len(userDB.users)
	if users != 1 {
		t.Errorf("expected 1 user (old employee), got %d", users)
	}
}

func TestHandleOIDCCallback_EmailReassignment_AllowedAfterDeactivation(t *testing.T) {
	// Test scenario: Admin deactivates old employee, then new employee can login
	providerDB := newMockOIDCProviderDB()
	linkDB := newMockOIDCLinkDB()
	sessionDB := newMockOIDCSessionDB()
	userDB := newMockUserDB()

	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:                 tenantID,
		ProviderName:             "Example Corp SSO",
		IssuerURL:                "https://sso.example.com",
		ClientID:                 "client-id",
		ClientSecret:             "client-secret",
		Scopes:                   []string{"openid", "email", "profile"},
		Enabled:                  true,
		AllowedDomains:           []string{"example.com"},
		AutoCreateUsers:          true,
		RequireEmailVerification: false,
	}
	provider, _ = providerDB.CreateOIDCProvider(context.Background(), provider)

	// Create old employee's account with OIDC link
	oldEmployee := &User{
		TenantID: tenantID,
		Email:    "employee@example.com",
		Status:   UserStatusActive,
	}
	oldEmployee, _ = userDB.CreateUser(context.Background(), oldEmployee)

	oldLink := &OIDCLink{
		UserID:         oldEmployee.ID,
		OIDCProviderID: provider.ID,
		ProviderUserID: "old-provider-sub-123",
		ProviderEmail:  "employee@example.com",
	}
	linkDB.CreateOIDCLink(context.Background(), oldLink)

	// Admin deletes old employee's account (simulating offboarding)
	userDB.DeleteUser(context.Background(), oldEmployee.ID)
	linkDB.DeleteOIDCLink(context.Background(), oldEmployee.ID, provider.ID)

	// Create session for new employee login
	state := "test-state"
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   "test-verifier",
		OIDCProviderID: &provider.ID,
		TenantID:       &tenantID,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	sessionDB.CreateOIDCSession(context.Background(), session)

	// New employee with same email but different provider sub
	mockProvider := &mockOIDCProvider{
		tokens: &OIDCTokenResponse{
			AccessToken: "access-token",
			IDToken:     "id-token",
		},
		userInfo: &OIDCUserInfo{
			Sub:           "new-provider-sub-456",
			Email:         "employee@example.com",
			EmailVerified: true,
			Name:          "New Employee",
		},
	}

	factory := &mockProviderFactory{provider: mockProvider}

	service := newTestOIDCService(providerDB, linkDB, sessionDB, userDB, factory, nil)

	// New employee login should succeed now
	user, link, err := service.HandleOIDCCallback(context.Background(), state, "auth-code")
	if err != nil {
		t.Fatalf("HandleOIDCCallback should succeed after old account deleted: %v", err)
	}

	if user == nil {
		t.Fatal("expected new user to be created")
	}
	if user.Email != "employee@example.com" {
		t.Errorf("expected email employee@example.com, got %s", user.Email)
	}
	if user.ID == oldEmployee.ID {
		t.Error("new user should have different ID than old employee")
	}

	if link == nil {
		t.Fatal("expected OIDC link to be created")
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

	providerDB := newMockOIDCProviderDB()
	linkDB := newMockOIDCLinkDB()
	sessionDB := newMockOIDCSessionDB()
	userDB := newMockUserDB()

	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:                 tenantID,
		ProviderName:             "Example Corp SSO",
		IssuerURL:                "https://sso.example.com",
		ClientID:                 "client-id",
		ClientSecret:             "client-secret",
		Scopes:                   []string{"openid", "email", "profile"},
		Enabled:                  true,
		AllowedDomains:           []string{"example.com"},
		AutoCreateUsers:          true,
		RequireEmailVerification: false,
	}
	provider, _ = providerDB.CreateOIDCProvider(context.Background(), provider)

	// Create user with old email
	user := &User{
		TenantID: tenantID,
		Email:    "oldemail@example.com",
		Status:   UserStatusActive,
	}
	user, _ = userDB.CreateUser(context.Background(), user)

	// Link with provider sub
	link := &OIDCLink{
		UserID:         user.ID,
		OIDCProviderID: provider.ID,
		ProviderUserID: "provider-sub-123",
		ProviderEmail:  "oldemail@example.com",
	}
	linkDB.CreateOIDCLink(context.Background(), link)

	// Create session
	state := "test-state"
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   "test-verifier",
		OIDCProviderID: &provider.ID,
		TenantID:       &tenantID,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	sessionDB.CreateOIDCSession(context.Background(), session)

	// User logs in with SAME provider sub but DIFFERENT email
	// (email was changed at the provider)
	mockProvider := &mockOIDCProvider{
		tokens: &OIDCTokenResponse{
			AccessToken: "access-token",
			IDToken:     "id-token",
		},
		userInfo: &OIDCUserInfo{
			Sub:           "provider-sub-123",     // Same provider sub
			Email:         "newemail@example.com", // Different email!
			EmailVerified: true,
			Name:          "Same User",
		},
	}

	factory := &mockProviderFactory{provider: mockProvider}

	service := newTestOIDCService(providerDB, linkDB, sessionDB, userDB, factory, nil)

	// Should succeed - we track by sub, not email
	returnedUser, returnedLink, err := service.HandleOIDCCallback(context.Background(), state, "auth-code")
	if err != nil {
		t.Fatalf("HandleOIDCCallback should succeed for same sub with different email: %v", err)
	}

	if returnedUser.ID != user.ID {
		t.Error("should return existing user")
	}
	if returnedLink.ID != link.ID {
		t.Error("should return existing link")
	}

	// Note: Link's ProviderEmail field is not automatically updated
	// This is tracked for reference but doesn't affect authentication
	// since we authenticate by immutable provider sub, not email
}

func TestHandleOIDCCallback_EmailNotVerified(t *testing.T) {
	providerDB := newMockOIDCProviderDB()
	sessionDB := newMockOIDCSessionDB()

	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:                 tenantID,
		ProviderName:             "Example Corp SSO",
		IssuerURL:                "https://sso.example.com",
		ClientID:                 "client-id",
		ClientSecret:             "client-secret",
		Scopes:                   []string{"openid", "email", "profile"},
		Enabled:                  true,
		AllowedDomains:           []string{"example.com"},
		AutoCreateUsers:          true,
		RequireEmailVerification: true, // Required!
	}
	provider, _ = providerDB.CreateOIDCProvider(context.Background(), provider)

	// Create session
	state := "test-state"
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   "test-verifier",
		OIDCProviderID: &provider.ID,
		TenantID:       &tenantID,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	sessionDB.CreateOIDCSession(context.Background(), session)

	mockProvider := &mockOIDCProvider{
		tokens: &OIDCTokenResponse{
			AccessToken: "access-token",
			IDToken:     "id-token",
		},
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

	factory := &mockProviderFactory{provider: mockProvider}

	service := newTestOIDCService(
		providerDB,
		newMockOIDCLinkDB(),
		sessionDB,
		newMockUserDB(),
		factory,
		nil,
	)

	_, _, err := service.HandleOIDCCallback(context.Background(), state, "auth-code")
	if !errors.Is(err, ErrProviderEmailNotVerified) {
		t.Errorf("expected ErrProviderEmailNotVerified, got: %v", err)
	}
}

// OAuth Flow Error Cases

func TestHandleOIDCCallback_TokenExchangeFailed(t *testing.T) {
	providerDB := newMockOIDCProviderDB()
	sessionDB := newMockOIDCSessionDB()

	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:        tenantID,
		ProviderName:    "Example Corp SSO",
		IssuerURL:       "https://sso.example.com",
		ClientID:        "client-id",
		ClientSecret:    "client-secret",
		Scopes:          []string{"openid", "email", "profile"},
		Enabled:         true,
		AllowedDomains:  []string{"example.com"},
		AutoCreateUsers: true,
	}
	provider, _ = providerDB.CreateOIDCProvider(context.Background(), provider)

	state := "test-state"
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   "test-verifier",
		OIDCProviderID: &provider.ID,
		TenantID:       &tenantID,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	sessionDB.CreateOIDCSession(context.Background(), session)

	// Mock provider returns error during token exchange
	mockProvider := &mockOIDCProvider{
		tokensError: errors.New("token exchange failed"),
	}

	factory := &mockProviderFactory{provider: mockProvider}

	service := newTestOIDCService(
		providerDB,
		newMockOIDCLinkDB(),
		sessionDB,
		newMockUserDB(),
		factory,
		nil,
	)

	_, _, err := service.HandleOIDCCallback(context.Background(), state, "auth-code")
	if err == nil {
		t.Error("expected error when token exchange fails")
	}
}

func TestHandleOIDCCallback_UserInfoFetchFailed(t *testing.T) {
	providerDB := newMockOIDCProviderDB()
	sessionDB := newMockOIDCSessionDB()

	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:        tenantID,
		ProviderName:    "Example Corp SSO",
		IssuerURL:       "https://sso.example.com",
		ClientID:        "client-id",
		ClientSecret:    "client-secret",
		Scopes:          []string{"openid", "email", "profile"},
		Enabled:         true,
		AllowedDomains:  []string{"example.com"},
		AutoCreateUsers: true,
	}
	provider, _ = providerDB.CreateOIDCProvider(context.Background(), provider)

	state := "test-state"
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   "test-verifier",
		OIDCProviderID: &provider.ID,
		TenantID:       &tenantID,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	sessionDB.CreateOIDCSession(context.Background(), session)

	// Token exchange succeeds but userinfo fetch fails
	mockProvider := &mockOIDCProvider{
		tokens: &OIDCTokenResponse{
			AccessToken: "access-token",
			IDToken:     "id-token",
		},
		userInfoError: errors.New("userinfo endpoint failed"),
	}

	factory := &mockProviderFactory{provider: mockProvider}

	service := newTestOIDCService(
		providerDB,
		newMockOIDCLinkDB(),
		sessionDB,
		newMockUserDB(),
		factory,
		nil,
	)

	_, _, err := service.HandleOIDCCallback(context.Background(), state, "auth-code")
	if err == nil {
		t.Error("expected error when userinfo fetch fails")
	}
}

// Session Security Tests

func TestHandleOIDCCallback_InvalidState(t *testing.T) {
	service := newTestOIDCService(
		newMockOIDCProviderDB(),
		newMockOIDCLinkDB(),
		newMockOIDCSessionDB(),
		newMockUserDB(),
		&mockProviderFactory{},
		nil,
	)

	// Attempt callback with state that doesn't exist
	_, _, err := service.HandleOIDCCallback(context.Background(), "invalid-state", "auth-code")
	if !errors.Is(err, ErrOIDCSessionNotFound) {
		t.Errorf("expected ErrOIDCSessionNotFound for invalid state, got: %v", err)
	}
}

func TestHandleOIDCCallback_ExpiredSession(t *testing.T) {
	providerDB := newMockOIDCProviderDB()
	sessionDB := newMockOIDCSessionDB()

	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:        tenantID,
		ProviderName:    "Example Corp SSO",
		IssuerURL:       "https://sso.example.com",
		ClientID:        "client-id",
		ClientSecret:    "client-secret",
		Scopes:          []string{"openid", "email", "profile"},
		Enabled:         true,
		AllowedDomains:  []string{"example.com"},
		AutoCreateUsers: true,
	}
	provider, _ = providerDB.CreateOIDCProvider(context.Background(), provider)

	state := "test-state"
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   "test-verifier",
		OIDCProviderID: &provider.ID,
		TenantID:       &tenantID,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}
	sessionDB.CreateOIDCSession(context.Background(), session)

	service := newTestOIDCService(
		providerDB,
		newMockOIDCLinkDB(),
		sessionDB,
		newMockUserDB(),
		&mockProviderFactory{},
		nil,
	)

	_, _, err := service.HandleOIDCCallback(context.Background(), state, "auth-code")
	if !errors.Is(err, ErrOIDCSessionNotFound) {
		t.Errorf("expected ErrOIDCSessionNotFound for expired session, got: %v", err)
	}
}

func TestStartOIDCLogin_GeneratesUniqueState(t *testing.T) {
	sessionDB := newMockOIDCSessionDB()

	mockProvider := &mockOIDCProvider{
		authURL: "https://accounts.google.com/o/oauth2/v2/auth",
	}

	systemProviders := map[sdk.OIDCProviderType]OIDCProvider{
		sdk.OIDCProviderTypeGoogle: mockProvider,
	}

	service := newTestOIDCService(
		newMockOIDCProviderDB(),
		newMockOIDCLinkDB(),
		sessionDB,
		newMockUserDB(),
		&mockProviderFactory{},
		systemProviders,
	)

	// Generate multiple sessions
	states := make(map[string]bool)
	for i := 0; i < 5; i++ {
		_, err := service.StartOIDCLogin(context.Background(), sdk.OIDCProviderTypeGoogle)
		if err != nil {
			t.Fatalf("StartOIDCLogin failed: %v", err)
		}
	}

	// Verify all states are unique
	for state := range sessionDB.sessions {
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
	sessionDB := newMockOIDCSessionDB()
	userDB := newMockUserDB()

	// Create session for individual OAuth (no tenant ID, has provider type)
	state := "test-state"
	providerType := sdk.OIDCProviderTypeGoogle
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   "test-verifier",
		OIDCProviderID: nil,           // No tenant-specific provider
		ProviderType:   &providerType, // System-wide provider
		TenantID:       nil,           // Tenant determined during callback
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	sessionDB.CreateOIDCSession(context.Background(), session)

	mockProvider := &mockOIDCProvider{
		tokens: &OIDCTokenResponse{
			AccessToken: "access-token",
			IDToken:     "id-token",
		},
		userInfo: &OIDCUserInfo{
			Sub:           "google-user-123",
			Email:         "newuser@gmail.com",
			EmailVerified: true,
			Name:          "New User",
		},
	}

	systemProviders := map[sdk.OIDCProviderType]OIDCProvider{
		sdk.OIDCProviderTypeGoogle: mockProvider,
	}

	service := newTestOIDCService(
		newMockOIDCProviderDB(),
		newMockOIDCLinkDB(),
		sessionDB,
		userDB,
		&mockProviderFactory{},
		systemProviders,
	)

	user, _, err := service.HandleOIDCCallback(context.Background(), state, "auth-code")
	if err != nil {
		t.Fatalf("HandleOIDCCallback failed: %v", err)
	}

	if user == nil {
		t.Fatal("expected user to be created")
	}
	if user.Email != "newuser@gmail.com" {
		t.Errorf("expected email newuser@gmail.com, got %s", user.Email)
	}
	if user.Status != UserStatusActive {
		t.Errorf("expected user status active, got %s", user.Status)
	}

	// Verify user got their own tenant
	if user.TenantID == uuid.Nil {
		t.Error("user should have a tenant ID")
	}
}

func TestHandleOIDCCallback_IndividualOAuth_ExistingUser(t *testing.T) {
	sessionDB := newMockOIDCSessionDB()
	userDB := newMockUserDB()

	// Create existing user
	existingUser := &User{
		TenantID: uuid.New(),
		Email:    "existing@gmail.com",
		Status:   UserStatusActive,
	}
	existingUser, _ = userDB.CreateUser(context.Background(), existingUser)

	// Create session for individual OAuth
	state := "test-state"
	providerType := sdk.OIDCProviderTypeGoogle
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   "test-verifier",
		OIDCProviderID: nil,
		ProviderType:   &providerType,
		TenantID:       nil,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	sessionDB.CreateOIDCSession(context.Background(), session)

	mockProvider := &mockOIDCProvider{
		tokens: &OIDCTokenResponse{
			AccessToken: "access-token",
			IDToken:     "id-token",
		},
		userInfo: &OIDCUserInfo{
			Sub:           "google-user-123",
			Email:         "existing@gmail.com",
			EmailVerified: true,
			Name:          "Existing User",
		},
	}

	systemProviders := map[sdk.OIDCProviderType]OIDCProvider{
		sdk.OIDCProviderTypeGoogle: mockProvider,
	}

	service := newTestOIDCService(
		newMockOIDCProviderDB(),
		newMockOIDCLinkDB(),
		sessionDB,
		userDB,
		&mockProviderFactory{},
		systemProviders,
	)

	user, _, err := service.HandleOIDCCallback(context.Background(), state, "auth-code")
	if err != nil {
		t.Fatalf("HandleOIDCCallback failed: %v", err)
	}

	if user.ID != existingUser.ID {
		t.Error("should return existing user")
	}
}

func TestHandleOIDCCallback_IndividualOAuth_EmailNotVerified(t *testing.T) {
	sessionDB := newMockOIDCSessionDB()

	state := "test-state"
	providerType := sdk.OIDCProviderTypeGoogle
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   "test-verifier",
		OIDCProviderID: nil,
		ProviderType:   &providerType,
		TenantID:       nil,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	sessionDB.CreateOIDCSession(context.Background(), session)

	mockProvider := &mockOIDCProvider{
		tokens: &OIDCTokenResponse{
			AccessToken: "access-token",
			IDToken:     "id-token",
		},
		userInfo: &OIDCUserInfo{
			Sub:           "google-user-123",
			Email:         "unverified@gmail.com",
			EmailVerified: false, // Not verified!
			Name:          "Unverified User",
		},
		claims: &OIDCClaims{
			EmailVerified: false,
		},
	}

	systemProviders := map[sdk.OIDCProviderType]OIDCProvider{
		sdk.OIDCProviderTypeGoogle: mockProvider,
	}

	service := newTestOIDCService(
		newMockOIDCProviderDB(),
		newMockOIDCLinkDB(),
		sessionDB,
		newMockUserDB(),
		&mockProviderFactory{},
		systemProviders,
	)

	_, _, err := service.HandleOIDCCallback(context.Background(), state, "auth-code")
	if !errors.Is(err, ErrProviderEmailNotVerified) {
		t.Errorf("expected ErrProviderEmailNotVerified, got: %v", err)
	}
}

// Missing Required Claims Tests

func TestHandleOIDCCallback_MissingSubClaim(t *testing.T) {
	providerDB := newMockOIDCProviderDB()
	sessionDB := newMockOIDCSessionDB()

	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:        tenantID,
		ProviderName:    "Example Corp SSO",
		IssuerURL:       "https://sso.example.com",
		ClientID:        "client-id",
		ClientSecret:    "client-secret",
		Scopes:          []string{"openid", "email", "profile"},
		Enabled:         true,
		AllowedDomains:  []string{"example.com"},
		AutoCreateUsers: true,
	}
	provider, _ = providerDB.CreateOIDCProvider(context.Background(), provider)

	state := "test-state"
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   "test-verifier",
		OIDCProviderID: &provider.ID,
		TenantID:       &tenantID,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	sessionDB.CreateOIDCSession(context.Background(), session)

	mockProvider := &mockOIDCProvider{
		tokens: &OIDCTokenResponse{
			AccessToken: "access-token",
			IDToken:     "id-token",
		},
		userInfo: &OIDCUserInfo{
			Sub:           "", // Missing sub!
			Email:         "user@example.com",
			EmailVerified: true,
			Name:          "User",
		},
	}

	factory := &mockProviderFactory{provider: mockProvider}

	service := newTestOIDCService(
		providerDB,
		newMockOIDCLinkDB(),
		sessionDB,
		newMockUserDB(),
		factory,
		nil,
	)

	_, _, err := service.HandleOIDCCallback(context.Background(), state, "auth-code")
	if err == nil {
		t.Error("expected error when sub claim is missing")
	}
}

func TestHandleOIDCCallback_MissingEmailClaim(t *testing.T) {
	providerDB := newMockOIDCProviderDB()
	sessionDB := newMockOIDCSessionDB()

	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:        tenantID,
		ProviderName:    "Example Corp SSO",
		IssuerURL:       "https://sso.example.com",
		ClientID:        "client-id",
		ClientSecret:    "client-secret",
		Scopes:          []string{"openid", "email", "profile"},
		Enabled:         true,
		AllowedDomains:  []string{"example.com"},
		AutoCreateUsers: true,
	}
	provider, _ = providerDB.CreateOIDCProvider(context.Background(), provider)

	state := "test-state"
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   "test-verifier",
		OIDCProviderID: &provider.ID,
		TenantID:       &tenantID,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	sessionDB.CreateOIDCSession(context.Background(), session)

	mockProvider := &mockOIDCProvider{
		tokens: &OIDCTokenResponse{
			AccessToken: "access-token",
			IDToken:     "id-token",
		},
		userInfo: &OIDCUserInfo{
			Sub:           "provider-user-123",
			Email:         "", // Missing email!
			EmailVerified: true,
			Name:          "User",
		},
	}

	factory := &mockProviderFactory{provider: mockProvider}

	service := newTestOIDCService(
		providerDB,
		newMockOIDCLinkDB(),
		sessionDB,
		newMockUserDB(),
		factory,
		nil,
	)

	_, _, err := service.HandleOIDCCallback(context.Background(), state, "auth-code")
	if err == nil {
		t.Error("expected error when email claim is missing")
	}
}

// OIDC Provider CRUD Tests

func TestCreateOIDCProvider_Success(t *testing.T) {
	providerDB := newMockOIDCProviderDB()
	service := newTestOIDCService(
		providerDB,
		newMockOIDCLinkDB(),
		newMockOIDCSessionDB(),
		newMockUserDB(),
		&mockProviderFactory{},
		nil,
	)

	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:                 tenantID,
		ProviderName:             "New Provider",
		IssuerURL:                "https://newprovider.com",
		ClientID:                 "client-123",
		ClientSecret:             "secret-456",
		Scopes:                   []string{"openid", "email"},
		Enabled:                  true,
		AllowedDomains:           []string{"newdomain.com"},
		AutoCreateUsers:          true,
		RequireEmailVerification: false,
	}

	result, err := service.CreateOIDCProvider(context.Background(), provider, "")
	if err != nil {
		t.Fatalf("CreateOIDCProvider failed: %v", err)
	}

	if result.ID == uuid.Nil {
		t.Error("provider should have an ID")
	}
	if result.ProviderName != "New Provider" {
		t.Errorf("expected provider name 'New Provider', got %s", result.ProviderName)
	}
}

func TestGetOIDCProvider_Success(t *testing.T) {
	providerDB := newMockOIDCProviderDB()

	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:       tenantID,
		ProviderName:   "Test Provider",
		IssuerURL:      "https://test.com",
		ClientID:       "client-123",
		ClientSecret:   "secret-456",
		Scopes:         []string{"openid"},
		Enabled:        true,
		AllowedDomains: []string{"test.com"},
	}
	provider, _ = providerDB.CreateOIDCProvider(context.Background(), provider)

	service := newTestOIDCService(
		providerDB,
		newMockOIDCLinkDB(),
		newMockOIDCSessionDB(),
		newMockUserDB(),
		&mockProviderFactory{},
		nil,
	)

	result, err := service.GetOIDCProvider(context.Background(), provider.ID)
	if err != nil {
		t.Fatalf("GetOIDCProvider failed: %v", err)
	}

	if result.ID != provider.ID {
		t.Error("should return the correct provider")
	}
}

func TestGetOIDCProvider_NotFound(t *testing.T) {
	service := newTestOIDCService(
		newMockOIDCProviderDB(),
		newMockOIDCLinkDB(),
		newMockOIDCSessionDB(),
		newMockUserDB(),
		&mockProviderFactory{},
		nil,
	)

	_, err := service.GetOIDCProvider(context.Background(), uuid.New())
	if !errors.Is(err, ErrOIDCProviderNotFound) {
		t.Errorf("expected ErrOIDCProviderNotFound, got: %v", err)
	}
}

func TestUpdateOIDCProvider_Success(t *testing.T) {
	providerDB := newMockOIDCProviderDB()

	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:       tenantID,
		ProviderName:   "Original Name",
		IssuerURL:      "https://test.com",
		ClientID:       "client-123",
		ClientSecret:   "secret-456",
		Scopes:         []string{"openid"},
		Enabled:        true,
		AllowedDomains: []string{"test.com"},
	}
	provider, _ = providerDB.CreateOIDCProvider(context.Background(), provider)

	service := newTestOIDCService(
		providerDB,
		newMockOIDCLinkDB(),
		newMockOIDCSessionDB(),
		newMockUserDB(),
		&mockProviderFactory{},
		nil,
	)

	newName := "Updated Name"
	params := &UpdateOIDCProviderParams{
		ID:           provider.ID,
		ProviderName: &newName,
	}

	result, err := service.UpdateOIDCProvider(context.Background(), params)
	if err != nil {
		t.Fatalf("UpdateOIDCProvider failed: %v", err)
	}

	if result.ProviderName != "Updated Name" {
		t.Errorf("expected provider name 'Updated Name', got %s", result.ProviderName)
	}
}

func TestDeleteOIDCProvider_Success(t *testing.T) {
	providerDB := newMockOIDCProviderDB()

	tenantID := uuid.New()
	provider := &OIDCProviderConfig{
		TenantID:       tenantID,
		ProviderName:   "To Delete",
		IssuerURL:      "https://test.com",
		ClientID:       "client-123",
		ClientSecret:   "secret-456",
		Scopes:         []string{"openid"},
		Enabled:        true,
		AllowedDomains: []string{"test.com"},
	}
	provider, _ = providerDB.CreateOIDCProvider(context.Background(), provider)

	service := newTestOIDCService(
		providerDB,
		newMockOIDCLinkDB(),
		newMockOIDCSessionDB(),
		newMockUserDB(),
		&mockProviderFactory{},
		nil,
	)

	err := service.DeleteOIDCProvider(context.Background(), provider.ID)
	if err != nil {
		t.Fatalf("DeleteOIDCProvider failed: %v", err)
	}

	// Verify it's deleted
	_, err = service.GetOIDCProvider(context.Background(), provider.ID)
	if !errors.Is(err, ErrOIDCProviderNotFound) {
		t.Error("provider should be deleted")
	}
}

func TestListOIDCProviders_Success(t *testing.T) {
	providerDB := newMockOIDCProviderDB()

	tenantID := uuid.New()

	// Create multiple providers
	for i := 0; i < 3; i++ {
		provider := &OIDCProviderConfig{
			TenantID:       tenantID,
			ProviderName:   "Provider " + string(rune(i)),
			IssuerURL:      "https://test.com",
			ClientID:       "client-123",
			ClientSecret:   "secret-456",
			Scopes:         []string{"openid"},
			Enabled:        true,
			AllowedDomains: []string{"test.com"},
		}
		providerDB.CreateOIDCProvider(context.Background(), provider)
	}

	service := newTestOIDCService(
		providerDB,
		newMockOIDCLinkDB(),
		newMockOIDCSessionDB(),
		newMockUserDB(),
		&mockProviderFactory{},
		nil,
	)

	providers, err := service.ListOIDCProviders(context.Background())
	if err != nil {
		t.Fatalf("ListOIDCProviders failed: %v", err)
	}

	if len(providers) != 3 {
		t.Errorf("expected 3 providers, got %d", len(providers))
	}
}

// Multi-tenancy Edge Cases

func TestStartSSOLogin_ProviderFromDifferentTenant(t *testing.T) {
	// This test documents that domain-based SSO discovery
	// doesn't have tenant isolation (domains are global)
	// This is intentional - domains are unique across all tenants
	providerDB := newMockOIDCProviderDB()

	tenant1 := uuid.New()

	// Tenant 1 configures example.com
	provider1 := &OIDCProviderConfig{
		TenantID:        tenant1,
		ProviderName:    "Tenant 1 Provider",
		IssuerURL:       "https://sso1.example.com",
		ClientID:        "client-1",
		ClientSecret:    "secret-1",
		Scopes:          []string{"openid"},
		Enabled:         true,
		AllowedDomains:  []string{"example.com"},
		AutoCreateUsers: true,
	}
	providerDB.CreateOIDCProvider(context.Background(), provider1)

	service := newTestOIDCService(
		providerDB,
		newMockOIDCLinkDB(),
		newMockOIDCSessionDB(),
		newMockUserDB(),
		&mockProviderFactory{provider: &mockOIDCProvider{authURL: "https://sso1.example.com/auth"}},
		nil,
	)

	// Any user with @example.com can start SSO
	authURL, err := service.StartSSOLogin(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("StartSSOLogin failed: %v", err)
	}

	if authURL == "" {
		t.Error("should generate auth URL")
	}
}

func TestHandleOIDCCallback_CreateUserInCorrectTenant(t *testing.T) {
	providerDB := newMockOIDCProviderDB()
	sessionDB := newMockOIDCSessionDB()
	userDB := newMockUserDB()

	tenant1 := uuid.New()

	provider := &OIDCProviderConfig{
		TenantID:        tenant1,
		ProviderName:    "Provider",
		IssuerURL:       "https://sso.example.com",
		ClientID:        "client-id",
		ClientSecret:    "secret",
		Scopes:          []string{"openid"},
		Enabled:         true,
		AllowedDomains:  []string{"example.com"},
		AutoCreateUsers: true,
	}
	provider, _ = providerDB.CreateOIDCProvider(context.Background(), provider)

	state := "test-state"
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   "verifier",
		OIDCProviderID: &provider.ID,
		TenantID:       &tenant1,
		RedirectURI:    "http://localhost:8080/v1/oauth/callback",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	sessionDB.CreateOIDCSession(context.Background(), session)

	mockProvider := &mockOIDCProvider{
		tokens: &OIDCTokenResponse{
			AccessToken: "token",
			IDToken:     "id-token",
		},
		userInfo: &OIDCUserInfo{
			Sub:           "sub-123",
			Email:         "user@example.com",
			EmailVerified: true,
		},
	}

	factory := &mockProviderFactory{provider: mockProvider}

	service := newTestOIDCService(
		providerDB,
		newMockOIDCLinkDB(),
		sessionDB,
		userDB,
		factory,
		nil,
	)

	user, _, err := service.HandleOIDCCallback(context.Background(), state, "code")
	if err != nil {
		t.Fatalf("HandleOIDCCallback failed: %v", err)
	}

	// Verify user created in correct tenant
	if user.TenantID != tenant1 {
		t.Errorf("user should be in tenant1, got %s", user.TenantID)
	}
}
