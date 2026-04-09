//go:build integration

package test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/identity"
	"github.com/travisbale/knowhere/jwt"
)

// UserClient holds an authenticated SDK client with the user's metadata
type UserClient struct {
	Client   *sdk.HTTPClient
	Email    string
	Password string
}

// CreateVerifiedUser registers a user, verifies email via DB token extraction, and returns an authenticated client
func CreateVerifiedUser(t *testing.T, name string, opts ...sdk.Option) *UserClient {
	t.Helper()

	email, password := GenerateTestCredentials(t, name)

	client := harness.NewClient(t, opts...)

	// Register
	_, err := client.Register(context.Background(), sdk.RegisterRequest{
		Email:     email,
		FirstName: "Test",
		LastName:  "User",
	})
	require.NoError(t, err, "registration failed for %s", email)

	// Extract verification token from database
	token := GetVerificationToken(t, harness.DB, email)

	// Verify email and set password
	_, err = client.VerifyEmail(context.Background(), sdk.VerifyEmailRequest{
		Token:    token,
		Password: password,
	})
	require.NoError(t, err, "email verification failed for %s", email)

	// Login to set access token on this client
	_, err = client.Login(context.Background(), sdk.LoginRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err, "login failed for %s", email)

	return &UserClient{
		Client:   client,
		Email:    email,
		Password: password,
	}
}

// CreateVerifiedUserWithJar creates a verified user with a controllable cookie jar
func CreateVerifiedUserWithJar(t *testing.T, name string) (*UserClient, *cookiejar.Jar) {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	user := CreateVerifiedUser(t, name, sdk.WithCookieJar(jar))
	return user, jar
}

// CreateAdminUser creates a verified user with all permissions granted via direct assignment.
// This gives the user full access to all RBAC, OIDC, and user management endpoints.
func CreateAdminUser(t *testing.T, name string) *UserClient {
	t.Helper()

	user := CreateVerifiedUser(t, name)
	ctx := context.Background()

	// Get all permissions
	perms, err := user.Client.ListPermissions(ctx)
	require.NoError(t, err)

	// Grant all permissions to the user
	var directPerms []sdk.DirectPermission
	for _, p := range perms.Permissions {
		directPerms = append(directPerms, sdk.DirectPermission{
			PermissionID: p.ID,
			Effect:       sdk.PermissionAllow,
		})
	}

	err = user.Client.SetDirectPermissions(ctx, sdk.SetDirectPermissionsRequest{
		UserID:      GetUserID(t, user.Email),
		Permissions: directPerms,
	})
	require.NoError(t, err)

	// Re-login to get JWT with updated scopes
	_, err = user.Client.Login(ctx, sdk.LoginRequest{
		Email:    user.Email,
		Password: user.Password,
	})
	require.NoError(t, err)

	return user
}

// CreateUserInTenant creates a user in an existing tenant via gRPC (no roles assigned).
// The admin user's tenant is used. Returns an authenticated client for the new user.
func CreateUserInTenant(t *testing.T, admin *UserClient, name string) *UserClient {
	t.Helper()

	email, password := GenerateTestCredentials(t, name)
	tenantID := GetTenantID(t, admin.Email)

	grpcClient, err := sdk.NewGRPCClient("localhost:9090")
	require.NoError(t, err)
	defer grpcClient.Close()

	ctx := identity.WithTenant(context.Background(), tenantID)

	resp, err := grpcClient.CreateUser(ctx, sdk.CreateUserRequest{
		Email: email,
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.VerificationToken)

	client := harness.NewClient(t)

	_, err = client.VerifyEmail(context.Background(), sdk.VerifyEmailRequest{
		Token:    resp.VerificationToken,
		Password: password,
	})
	require.NoError(t, err)

	_, err = client.Login(context.Background(), sdk.LoginRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)

	return &UserClient{
		Client:   client,
		Email:    email,
		Password: password,
	}
}

// GetTenantID retrieves the tenant ID from the database by user email
func GetTenantID(t *testing.T, email string) uuid.UUID {
	t.Helper()

	var id uuid.UUID
	err := harness.DB.QueryRow(context.Background(),
		`SELECT tenant_id FROM users WHERE email = $1`, email).Scan(&id)
	require.NoError(t, err, "failed to get tenant ID for %s", email)

	return id
}

// GetUserID retrieves the user ID from the database by email
func GetUserID(t *testing.T, email string) uuid.UUID {
	t.Helper()

	var id uuid.UUID
	err := harness.DB.QueryRow(context.Background(),
		`SELECT id FROM users WHERE email = $1`, email).Scan(&id)
	require.NoError(t, err, "failed to get user ID for %s", email)

	return id
}

// GetPermissionByName finds a permission by name from the permissions list
func GetPermissionByName(t *testing.T, client *sdk.HTTPClient, name string) sdk.Permission {
	t.Helper()

	perms, err := client.ListPermissions(context.Background())
	require.NoError(t, err)

	for _, p := range perms.Permissions {
		if p.Name == name {
			return p
		}
	}

	t.Fatalf("permission %q not found", name)
	return sdk.Permission{}
}

// FindRefreshCookie extracts the refresh token cookie from a cookie jar.
// The cookie is set on the /v1/refresh path, so we must use the full path for lookup.
func FindRefreshCookie(t *testing.T, jar *cookiejar.Jar) *http.Cookie {
	t.Helper()

	u, _ := url.Parse(harness.BaseURL + sdk.RouteV1Refresh)
	for _, c := range jar.Cookies(u) {
		if c.Name == "refresh_token" {
			return c
		}
	}

	t.Fatal("refresh_token cookie not found")
	return nil
}

// NewClientWithCookie creates an SDK client with a specific cookie set
func NewClientWithCookie(t *testing.T, cookie *http.Cookie) *sdk.HTTPClient {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	u, _ := url.Parse(harness.BaseURL)
	jar.SetCookies(u, []*http.Cookie{cookie})

	client, err := sdk.NewHTTPClient(harness.BaseURL, sdk.WithCookieJar(jar))
	require.NoError(t, err)

	return client
}

// ExtractClaims validates a token and returns its claims
func ExtractClaims(t *testing.T, token string) *jwt.Claims {
	t.Helper()
	claims, err := harness.Validator.ValidateToken(token)
	require.NoError(t, err, "failed to validate token")
	return claims
}

// ExtractMFAChallengeClaims validates an MFA challenge token and returns its claims
func ExtractMFAChallengeClaims(t *testing.T, token string) *jwt.Claims {
	t.Helper()
	claims, err := harness.Validator.ValidateMFAChallengeToken(token)
	require.NoError(t, err, "failed to validate MFA challenge token")
	return claims
}

// RawRequest sends an HTTP request directly to the server, bypassing SDK client-side validation.
// Returns the response status code and body as a string.
func RawRequest(t *testing.T, method, path, body, accessToken string) (int, string) {
	t.Helper()

	req, err := http.NewRequest(method, harness.BaseURL+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, string(respBody)
}

// getAccessToken logs in and returns the raw access token for use in raw HTTP requests
func getAccessToken(t *testing.T, user *UserClient) string {
	t.Helper()
	client := harness.NewClient(t)
	resp, err := client.Login(context.Background(), sdk.LoginRequest{
		Email:    user.Email,
		Password: user.Password,
	})
	require.NoError(t, err)
	return resp.AccessToken
}

// GenerateTestCredentials generates unique email and password using nanosecond timestamps
func GenerateTestCredentials(t *testing.T, name string) (string, string) {
	t.Helper()

	ts := time.Now().UnixNano()
	email := fmt.Sprintf("%s-%d@test.example.com", name, ts)
	password := fmt.Sprintf("TestPass-%d!", ts)

	return email, password
}

// AssertAPIError validates that an error is an APIError with the expected status code
func AssertAPIError(t *testing.T, err error, statusCode int, message string) {
	t.Helper()
	if !assert.Error(t, err, message) {
		return
	}
	apiErr, ok := errors.AsType[*sdk.APIError](err)
	if !assert.True(t, ok, "expected APIError, got: %T", err) {
		return
	}
	assert.Equal(t, statusCode, apiErr.StatusCode, message)
}
