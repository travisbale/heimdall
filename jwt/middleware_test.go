package jwt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
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

// Test helpers

// newValidClaims creates a Claims struct with valid UserID, TenantID, and optional scopes
func newValidClaims(userID, tenantID uuid.UUID, scopes ...sdk.Scope) *Claims {
	return &Claims{
		UserID:   userID,
		TenantID: tenantID,
		Scopes:   scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: userID.String(),
		},
	}
}

// newMockValidator creates a mock validator with the given claims
func newMockValidator(claims *Claims) *mockValidator {
	return &mockValidator{claims: claims}
}

// newMockValidatorWithError creates a mock validator that returns an error
func newMockValidatorWithError(err error) *mockValidator {
	return &mockValidator{err: err}
}

// testRequest executes a request through the middleware and returns the response recorder
func testRequest(handler http.Handler, authToken string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	if authToken != "" {
		req.Header.Set("Authorization", authToken)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// testHandler creates a simple handler that returns 200 OK
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

	claims := newValidClaims(userID, tenantID, sdk.ScopeUserRead)
	validator := newMockValidator(claims)
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.Authenticate(testHandler())

	rec := testRequest(handler, "Bearer valid-token")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestMiddleware_MissingAuthorizationHeader(t *testing.T) {
	validator := newMockValidator(nil)
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.Authenticate(testHandler())

	rec := testRequest(handler, "")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestMiddleware_InvalidAuthorizationFormat(t *testing.T) {
	validator := newMockValidator(nil)
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.Authenticate(testHandler())

	testCases := []string{
		"InvalidFormat",
		"Bearer",
		"Basic token",
		"Bearer token with spaces",
	}

	for _, authHeader := range testCases {
		rec := testRequest(handler, authHeader)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("auth header '%s': expected status 401, got %d", authHeader, rec.Code)
		}
	}
}

func TestMiddleware_InvalidToken(t *testing.T) {
	validator := newMockValidatorWithError(ErrInvalidToken)
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.Authenticate(testHandler())

	rec := testRequest(handler, "Bearer invalid-token")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestMiddleware_InvalidUserID(t *testing.T) {
	// Mock validator returns error for invalid UserID (real validator would catch this)
	validator := newMockValidatorWithError(ErrMissingClaims)
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.Authenticate(testHandler())

	rec := testRequest(handler, "Bearer valid-token")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestGetJWTClaims_Success(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()
	claims := newValidClaims(userID, tenantID, sdk.ScopeUserRead, sdk.ScopeUserUpdate)

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

// RequireScope Tests

func TestRequireScope_Success(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	claims := newValidClaims(userID, tenantID, sdk.ScopeUserRead, sdk.ScopeUserUpdate, sdk.Scope("delete:users"))
	validator := newMockValidator(claims)
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScope(sdk.ScopeUserRead, sdk.ScopeUserUpdate)(testHandler())

	rec := testRequest(handler, "Bearer valid-token")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestRequireScope_MissingScope(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	claims := newValidClaims(userID, tenantID, sdk.ScopeUserRead) // Missing write:users
	validator := newMockValidator(claims)
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScope(sdk.ScopeUserRead, sdk.ScopeUserUpdate)(testHandler())

	rec := testRequest(handler, "Bearer valid-token")

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestRequireScope_NoPermissions(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	claims := newValidClaims(userID, tenantID) // No permissions
	validator := newMockValidator(claims)
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScope(sdk.ScopeUserRead)(testHandler())

	rec := testRequest(handler, "Bearer valid-token")

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestRequireScope_EmptyRequired(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	claims := newValidClaims(userID, tenantID)
	validator := newMockValidator(claims)
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScope()(testHandler()) // No scopes required

	rec := testRequest(handler, "Bearer valid-token")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestRequireScope_MissingAuthHeader(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	claims := newValidClaims(userID, tenantID, sdk.ScopeUserRead)
	validator := newMockValidator(claims)
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScope(sdk.ScopeUserRead)(testHandler())

	rec := testRequest(handler, "") // No Authorization header

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestRequireScope_InvalidToken(t *testing.T) {
	validator := newMockValidatorWithError(ErrInvalidToken)
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScope(sdk.ScopeUserRead)(testHandler())

	rec := testRequest(handler, "Bearer invalid-token")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestRequireScope_SingleScope(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	claims := newValidClaims(userID, tenantID, sdk.Scope("admin:all"))
	validator := newMockValidator(claims)
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScope(sdk.Scope("admin:all"))(testHandler())

	rec := testRequest(handler, "Bearer valid-token")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

// Authenticate alone (no scope checking)

func TestAuthenticateAlone_Success(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	claims := newValidClaims(userID, tenantID, sdk.ScopeUserRead)
	validator := newMockValidator(claims)
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.Authenticate(testHandler()) // Use Authenticate alone for endpoints that don't need scope checking

	rec := testRequest(handler, "Bearer valid-token")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestRequireScope_WithInvalidToken(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	claims := newValidClaims(userID, tenantID, sdk.ScopeUserRead) // Missing write:users
	validator := newMockValidator(claims)
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScope(sdk.ScopeUserRead, sdk.ScopeUserUpdate)(testHandler()) // RequireScope validates JWT and checks scopes in one step

	rec := testRequest(handler, "Bearer valid-token")

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

// Struct-based API Tests

func TestHTTPMiddleware_Authenticate(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	claims := newValidClaims(userID, tenantID, sdk.ScopeUserRead)
	validator := newMockValidator(claims)
	jwtMiddleware := NewHTTPMiddleware(validator) // Create middleware instance
	handler := jwtMiddleware.Authenticate(testHandler())

	rec := testRequest(handler, "Bearer valid-token")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestHTTPMiddleware_RequireScope_Success(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	claims := newValidClaims(userID, tenantID, sdk.ScopeUserRead, sdk.ScopeUserUpdate)
	validator := newMockValidator(claims)
	jwtMiddleware := NewHTTPMiddleware(validator)                           // Create middleware instance once
	handler := jwtMiddleware.RequireScope(sdk.ScopeUserRead)(testHandler()) // Use it for multiple endpoints

	rec := testRequest(handler, "Bearer valid-token")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestHTTPMiddleware_RequireScope_MissingScope(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	claims := newValidClaims(userID, tenantID, sdk.ScopeUserRead)
	validator := newMockValidator(claims)
	jwtMiddleware := NewHTTPMiddleware(validator)
	handler := jwtMiddleware.RequireScope(sdk.ScopeUserRead, sdk.ScopeUserUpdate)(testHandler())

	rec := testRequest(handler, "Bearer valid-token")

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestHTTPMiddleware_MultipleEndpoints(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	claims := newValidClaims(userID, tenantID, sdk.ScopeUserRead, sdk.ScopeUserUpdate, sdk.Scope("admin:all"))
	validator := newMockValidator(claims)
	jwtMiddleware := NewHTTPMiddleware(validator) // Create middleware once

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
			handler := jwtMiddleware.RequireScope(tc.scopes...)(testHandler())

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
