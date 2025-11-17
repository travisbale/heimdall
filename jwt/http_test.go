package jwt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// Mock validator for HTTP middleware tests
type mockValidator struct {
	claims *Claims
	err    error
}

func (m *mockValidator) ValidateToken(token string) (*Claims, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.claims, nil
}

// Helper to create a test handler that returns 200 OK
func testHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"success"}`))
	})
}

// Middleware Tests

func TestMiddleware_Success(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	validator := &mockValidator{
		claims: &Claims{
			TenantID: tenantID,
			Scopes:   []sdk.Scope{sdk.ScopeUserRead},
		},
	}
	validator.claims.Subject = userID.String()

	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.Authenticate()(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestMiddleware_MissingAuthorizationHeader(t *testing.T) {
	validator := &mockValidator{}
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.Authenticate()(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestMiddleware_InvalidAuthorizationFormat(t *testing.T) {
	validator := &mockValidator{}
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.Authenticate()(testHandler())

	testCases := []string{
		"InvalidFormat",
		"Bearer",
		"Basic token",
		"Bearer token with spaces",
	}

	for _, authHeader := range testCases {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", authHeader)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("auth header '%s': expected status 401, got %d", authHeader, rec.Code)
		}
	}
}

func TestMiddleware_InvalidToken(t *testing.T) {
	validator := &mockValidator{
		err: ErrInvalidToken,
	}

	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.Authenticate()(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestMiddleware_InvalidUserID(t *testing.T) {
	validator := &mockValidator{
		claims: &Claims{
			TenantID: uuid.New(),
		},
	}
	validator.claims.Subject = "not-a-uuid"

	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.Authenticate()(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestGetJWTClaims_Success(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()
	scopes := []sdk.Scope{sdk.ScopeUserRead, sdk.ScopeUserUpdate}

	claims := &Claims{
		TenantID: tenantID,
		Scopes:   scopes,
	}
	claims.Subject = userID.String()

	// Create request with claims in context
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := context.WithValue(req.Context(), claimsContextKey, claims)
	req = req.WithContext(ctx)

	retrievedClaims, err := GetJWTClaims(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrievedClaims.Subject != userID.String() {
		t.Errorf("expected subject %s, got %s", userID.String(), retrievedClaims.Subject)
	}

	if retrievedClaims.TenantID != tenantID {
		t.Errorf("expected tenant ID %s, got %s", tenantID, retrievedClaims.TenantID)
	}

	if len(retrievedClaims.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(retrievedClaims.Scopes))
	}
}

func TestGetJWTClaims_NoClaimsInContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	_, err := GetJWTClaims(req)
	if err == nil {
		t.Error("expected error when no claims in context")
	}
}

// RequireScopes Tests

func TestRequireScopes_Success(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	validator := &mockValidator{
		claims: &Claims{
			TenantID: tenantID,
			Scopes:   []sdk.Scope{sdk.ScopeUserRead, sdk.ScopeUserUpdate, sdk.Scope("delete:users")},
		},
	}
	validator.claims.Subject = userID.String()

	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScopes([]sdk.Scope{sdk.ScopeUserRead, sdk.ScopeUserUpdate})(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestRequireScopes_MissingScope(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	validator := &mockValidator{
		claims: &Claims{
			TenantID: tenantID,
			Scopes:   []sdk.Scope{sdk.ScopeUserRead}, // Missing write:users
		},
	}
	validator.claims.Subject = userID.String()

	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScopes([]sdk.Scope{sdk.ScopeUserRead, sdk.ScopeUserUpdate})(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestRequireScopes_NoPermissions(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	validator := &mockValidator{
		claims: &Claims{
			TenantID: tenantID,
			Scopes:   []sdk.Scope{}, // No permissions
		},
	}
	validator.claims.Subject = userID.String()

	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScopes([]sdk.Scope{sdk.ScopeUserRead})(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestRequireScopes_EmptyRequired(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	validator := &mockValidator{
		claims: &Claims{
			TenantID: tenantID,
			Scopes:   []sdk.Scope{},
		},
	}
	validator.claims.Subject = userID.String()

	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScopes([]sdk.Scope{})(testHandler()) // No scopes required

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestRequireScopes_MissingAuthHeader(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	validator := &mockValidator{
		claims: &Claims{
			TenantID: tenantID,
			Scopes:   []sdk.Scope{sdk.ScopeUserRead},
		},
	}
	validator.claims.Subject = userID.String()

	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScopes([]sdk.Scope{sdk.ScopeUserRead})(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// No Authorization header
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestRequireScopes_InvalidToken(t *testing.T) {
	validator := &mockValidator{
		err: ErrInvalidToken,
	}

	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScopes([]sdk.Scope{sdk.ScopeUserRead})(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestRequireScopes_SingleScope(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	validator := &mockValidator{
		claims: &Claims{
			TenantID: tenantID,
			Scopes:   []sdk.Scope{sdk.Scope("admin:all")},
		},
	}
	validator.claims.Subject = userID.String()

	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScopes([]sdk.Scope{sdk.Scope("admin:all")})(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

// Authenticate alone (no scope checking)

func TestAuthenticateAlone_Success(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	validator := &mockValidator{
		claims: &Claims{
			TenantID: tenantID,
			Scopes:   []sdk.Scope{sdk.ScopeUserRead},
		},
	}
	validator.claims.Subject = userID.String()

	// Use Authenticate alone for endpoints that don't need scope checking
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.Authenticate()(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestRequireScopes_WithInvalidToken(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	validator := &mockValidator{
		claims: &Claims{
			TenantID: tenantID,
			Scopes:   []sdk.Scope{sdk.ScopeUserRead}, // Missing write:users
		},
	}
	validator.claims.Subject = userID.String()

	// RequireScopes validates JWT and checks scopes in one step
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScopes([]sdk.Scope{sdk.ScopeUserRead, sdk.ScopeUserUpdate})(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

// Struct-based API Tests

func TestHTTPMiddleware_Authenticate(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	validator := &mockValidator{
		claims: &Claims{
			TenantID: tenantID,
			Scopes:   []sdk.Scope{sdk.ScopeUserRead},
		},
	}
	validator.claims.Subject = userID.String()

	// Create middleware instance
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.Authenticate()(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestHTTPMiddleware_RequireScopes_Success(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	validator := &mockValidator{
		claims: &Claims{
			TenantID: tenantID,
			Scopes:   []sdk.Scope{sdk.ScopeUserRead, sdk.ScopeUserUpdate},
		},
	}
	validator.claims.Subject = userID.String()

	// Create middleware instance once
	jwtMiddleware := NewHTTPMiddleware(validator)

	// Use it for multiple endpoints
	handler := jwtMiddleware.RequireScopes([]sdk.Scope{sdk.ScopeUserRead})(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestHTTPMiddleware_RequireScopes_MissingScope(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	validator := &mockValidator{
		claims: &Claims{
			TenantID: tenantID,
			Scopes:   []sdk.Scope{sdk.ScopeUserRead},
		},
	}
	validator.claims.Subject = userID.String()

	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScopes([]sdk.Scope{sdk.ScopeUserRead, sdk.ScopeUserUpdate})(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestHTTPMiddleware_MultipleEndpoints(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	validator := &mockValidator{
		claims: &Claims{
			TenantID: tenantID,
			Scopes:   []sdk.Scope{sdk.ScopeUserRead, sdk.ScopeUserUpdate, sdk.Scope("admin:all")},
		},
	}
	validator.claims.Subject = userID.String()

	// Create middleware once
	jwtMiddleware := NewHTTPMiddleware(validator)

	// Simulate different endpoints with different scope requirements
	testCases := []struct {
		name           string
		scopes         []sdk.Scope
		expectedStatus int
	}{
		{"read only", []sdk.Scope{sdk.ScopeUserRead}, http.StatusOK},
		{"read and write", []sdk.Scope{sdk.ScopeUserRead, sdk.ScopeUserUpdate}, http.StatusOK},
		{"admin", []sdk.Scope{sdk.Scope("admin:all")}, http.StatusOK},
		{"missing scope", []sdk.Scope{sdk.Scope("delete:users")}, http.StatusForbidden},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := jwtMiddleware.RequireScopes(tc.scopes)(testHandler())

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", "Bearer valid-token")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, rec.Code)
			}
		})
	}
}
