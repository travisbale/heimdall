package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// Mock implementations for testing

// OIDC/OAuth Mocks

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

// User and Tenant Mocks

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

type mockTenantsDB struct {
	tenants map[uuid.UUID]*Tenant
}

func newMockTenantsDB() *mockTenantsDB {
	return &mockTenantsDB{
		tenants: make(map[uuid.UUID]*Tenant),
	}
}

func (m *mockTenantsDB) CreateTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error) {
	tenant := &Tenant{
		ID:        tenantID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	m.tenants[tenantID] = tenant
	return tenant, nil
}

func (m *mockTenantsDB) GetTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error) {
	tenant, ok := m.tenants[tenantID]
	if !ok {
		return nil, errors.New("tenant not found")
	}
	return tenant, nil
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

// Infrastructure Mocks

type mockLogger struct{}

func (m *mockLogger) Info(ctx context.Context, msg string, args ...any)  {}
func (m *mockLogger) Warn(ctx context.Context, msg string, args ...any)  {}
func (m *mockLogger) Error(ctx context.Context, msg string, args ...any) {}
func (m *mockLogger) Debug(ctx context.Context, msg string, args ...any) {}

// RBAC Mock implementations

type mockRoleRepository struct {
	roles       map[uuid.UUID]*Role
	createError error
	getError    error
	listError   error
	updateError error
	deleteError error
}

func newMockRoleRepository() *mockRoleRepository {
	return &mockRoleRepository{
		roles: make(map[uuid.UUID]*Role),
	}
}

func (m *mockRoleRepository) CreateRole(ctx context.Context, name, description string) (*Role, error) {
	if m.createError != nil {
		return nil, m.createError
	}
	role := &Role{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Name:        name,
		Description: description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	m.roles[role.ID] = role
	return role, nil
}

func (m *mockRoleRepository) GetRoleByID(ctx context.Context, roleID uuid.UUID) (*Role, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	role, ok := m.roles[roleID]
	if !ok {
		return nil, ErrRoleNotFound
	}
	return role, nil
}

func (m *mockRoleRepository) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	for _, role := range m.roles {
		if role.Name == name {
			return role, nil
		}
	}
	return nil, ErrRoleNotFound
}

func (m *mockRoleRepository) ListRoles(ctx context.Context) ([]*Role, error) {
	if m.listError != nil {
		return nil, m.listError
	}
	roles := make([]*Role, 0, len(m.roles))
	for _, role := range m.roles {
		roles = append(roles, role)
	}
	return roles, nil
}

func (m *mockRoleRepository) UpdateRole(ctx context.Context, roleID uuid.UUID, name, description string) (*Role, error) {
	if m.updateError != nil {
		return nil, m.updateError
	}
	role, ok := m.roles[roleID]
	if !ok {
		return nil, ErrRoleNotFound
	}
	role.Name = name
	role.Description = description
	role.UpdatedAt = time.Now()
	return role, nil
}

func (m *mockRoleRepository) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	if m.deleteError != nil {
		return m.deleteError
	}
	if _, ok := m.roles[roleID]; !ok {
		return ErrRoleNotFound
	}
	delete(m.roles, roleID)
	return nil
}

type mockPermissionRepository struct {
	permissions       map[uuid.UUID]*Permission
	userPermissions   map[uuid.UUID][]*EffectivePermission
	listError         error
	getError          error
	getUserPermsError error
}

func newMockPermissionRepository() *mockPermissionRepository {
	return &mockPermissionRepository{
		permissions:     make(map[uuid.UUID]*Permission),
		userPermissions: make(map[uuid.UUID][]*EffectivePermission),
	}
}

func (m *mockPermissionRepository) ListPermissions(ctx context.Context) ([]*Permission, error) {
	if m.listError != nil {
		return nil, m.listError
	}
	perms := make([]*Permission, 0, len(m.permissions))
	for _, perm := range m.permissions {
		perms = append(perms, perm)
	}
	return perms, nil
}

func (m *mockPermissionRepository) GetPermissionByID(ctx context.Context, permissionID uuid.UUID) (*Permission, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	perm, ok := m.permissions[permissionID]
	if !ok {
		return nil, ErrPermissionNotFound
	}
	return perm, nil
}

func (m *mockPermissionRepository) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*EffectivePermission, error) {
	if m.getUserPermsError != nil {
		return nil, m.getUserPermsError
	}
	perms, ok := m.userPermissions[userID]
	if !ok {
		return []*EffectivePermission{}, nil
	}
	return perms, nil
}

type mockRolePermissionRepository struct{}

func (m *mockRolePermissionRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*Permission, error) {
	return []*Permission{}, nil
}

func (m *mockRolePermissionRepository) SetRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	return nil
}

type mockUserRoleRepository struct{}

func (m *mockUserRoleRepository) SetUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	return nil
}

func (m *mockUserRoleRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*Role, error) {
	return []*Role{}, nil
}

type mockUserPermissionRepository struct{}

func (m *mockUserPermissionRepository) SetDirectPermissions(ctx context.Context, userID uuid.UUID, permissions []DirectPermission) error {
	return nil
}

func (m *mockUserPermissionRepository) GetDirectPermissions(ctx context.Context, userID uuid.UUID) ([]*EffectivePermission, error) {
	return []*EffectivePermission{}, nil
}

// Authentication and Security Mocks

type mockHasher struct {
	hashResult  string
	hashError   error
	verifyError error
}

func (m *mockHasher) HashPassword(password string) (string, error) {
	if m.hashError != nil {
		return "", m.hashError
	}
	if m.hashResult != "" {
		return m.hashResult, nil
	}
	return "hashed_" + password, nil
}

func (m *mockHasher) VerifyPassword(password, encodedHash string) error {
	if m.verifyError != nil {
		return m.verifyError
	}
	// Simple mock verification - check if hash matches "hashed_" + password
	if encodedHash == "hashed_"+password {
		return nil
	}
	return ErrInvalidCredentials
}

type mockEmailClient struct {
	verificationEmailError  error
	passwordResetEmailError error
	verificationEmails      []string
	passwordResetEmails     []string
}

func (m *mockEmailClient) SendVerificationEmail(ctx context.Context, email, token string) error {
	if m.verificationEmailError != nil {
		return m.verificationEmailError
	}
	m.verificationEmails = append(m.verificationEmails, email)
	return nil
}

func (m *mockEmailClient) SendPasswordResetEmail(ctx context.Context, email, token string) error {
	if m.passwordResetEmailError != nil {
		return m.passwordResetEmailError
	}
	m.passwordResetEmails = append(m.passwordResetEmails, email)
	return nil
}

type mockTokenDB struct {
	tokens      map[string]*UserToken
	createError error
	getError    error
	deleteError error
}

func newMockTokenDB() *mockTokenDB {
	return &mockTokenDB{
		tokens: make(map[string]*UserToken),
	}
}

func (m *mockTokenDB) CreateToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*UserToken, error) {
	if m.createError != nil {
		return nil, m.createError
	}
	t := &UserToken{
		UserID:    userID,
		Token:     token,
		ExpiresAt: expiresAt,
	}
	m.tokens[token] = t
	return t, nil
}

func (m *mockTokenDB) GetToken(ctx context.Context, token string) (*UserToken, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	t, ok := m.tokens[token]
	if !ok {
		return nil, ErrVerificationTokenNotFound
	}
	return t, nil
}

func (m *mockTokenDB) DeleteToken(ctx context.Context, userID uuid.UUID) error {
	if m.deleteError != nil {
		return m.deleteError
	}
	for token, t := range m.tokens {
		if t.UserID == userID {
			delete(m.tokens, token)
			return nil
		}
	}
	return nil
}

type mockLoginAttemptsService struct {
	locked             bool
	lockedUntil        time.Time
	lockError          error
	recordFailedError  error
	recordSuccessError error
	failedAttempts     []string
	successfulAttempts []string
}

func (m *mockLoginAttemptsService) IsAccountLocked(ctx context.Context, email string) (bool, time.Time, error) {
	if m.lockError != nil {
		return false, time.Time{}, m.lockError
	}
	return m.locked, m.lockedUntil, nil
}

func (m *mockLoginAttemptsService) RecordFailedLogin(ctx context.Context, email string, userID *uuid.UUID, ipAddress string, lastLoginAt *time.Time) error {
	if m.recordFailedError != nil {
		return m.recordFailedError
	}
	m.failedAttempts = append(m.failedAttempts, email)
	return nil
}

func (m *mockLoginAttemptsService) RecordSuccessfulLogin(ctx context.Context, email string, userID *uuid.UUID, ipAddress string) error {
	if m.recordSuccessError != nil {
		return m.recordSuccessError
	}
	m.successfulAttempts = append(m.successfulAttempts, email)
	return nil
}

type mockOIDCServiceForUser struct {
	ssoRequired bool
	ssoError    error
}

func (m *mockOIDCServiceForUser) IsSSORequired(ctx context.Context, email string) (bool, error) {
	if m.ssoError != nil {
		return false, m.ssoError
	}
	return m.ssoRequired, nil
}

type mockRBACService struct {
	setupSystemAdminRoleError error
	setUserRolesError         error
	userScopes                map[uuid.UUID][]sdk.Scope
}

func newMockRBACService() *mockRBACService {
	return &mockRBACService{
		userScopes: make(map[uuid.UUID][]sdk.Scope),
	}
}

func (m *mockRBACService) GetUserScopes(ctx context.Context, userID uuid.UUID) ([]sdk.Scope, error) {
	scopes, ok := m.userScopes[userID]
	if !ok {
		return []sdk.Scope{}, nil
	}
	return scopes, nil
}

func (m *mockRBACService) SetupSystemAdminRole(ctx context.Context, userID uuid.UUID) error {
	if m.setupSystemAdminRoleError != nil {
		return m.setupSystemAdminRoleError
	}
	// Simulate successful setup by granting all scopes to the user
	m.userScopes[userID] = []sdk.Scope{
		sdk.ScopeUserCreate,
		sdk.ScopeUserRead,
		sdk.ScopeUserUpdate,
		sdk.ScopeUserDelete,
		sdk.ScopeUserAssign,
		sdk.ScopeRoleCreate,
		sdk.ScopeRoleRead,
		sdk.ScopeRoleUpdate,
		sdk.ScopeRoleDelete,
		sdk.ScopeOIDCCreate,
		sdk.ScopeOIDCRead,
		sdk.ScopeOIDCUpdate,
		sdk.ScopeOIDCDelete,
	}
	return nil
}

func (m *mockRBACService) SetUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	if m.setUserRolesError != nil {
		return m.setUserRolesError
	}
	// Mock implementation - just succeed without actually doing anything
	return nil
}
