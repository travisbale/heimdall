package setup

import (
	"context"
	"fmt"
	"net/http/cookiejar"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	util "github.com/travisbale/heimdall/test/_util"
	"github.com/travisbale/heimdall/test/_util/database"
	"github.com/travisbale/heimdall/test/_util/jwt"
	"github.com/travisbale/knowhere/identity"
)

// CreateVerifiedUser registers a user, verifies email via DB token extraction, and returns an authenticated client
func CreateVerifiedUser(t *testing.T, name string, opts ...sdk.Option) *UserClient {
	t.Helper()

	email, password := GenerateTestCredentials(t, name)
	client := CreateClient(t, opts...)

	_, err := client.Register(context.Background(), sdk.RegisterRequest{
		Email:     email,
		FirstName: "Test",
		LastName:  "User",
	})
	require.NoError(t, err, "registration failed for %s", email)

	token := database.GetVerificationToken(t, email)

	verifyResp, err := client.VerifyEmail(context.Background(), sdk.VerifyEmailRequest{
		Token:    token,
		Password: password,
	})
	require.NoError(t, err, "email verification failed for %s", email)

	userID := jwt.ExtractUserID(t, verifyResp.AccessToken)
	tenantID := jwt.ExtractTenantID(t, verifyResp.AccessToken)

	_, err = client.Login(context.Background(), sdk.LoginRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err, "login failed for %s", email)

	return &UserClient{
		Client:   client,
		UserID:   userID,
		TenantID: tenantID,
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

// CreateAdminUser creates a verified user with all permissions granted via direct assignment
func CreateAdminUser(t *testing.T, name string) *UserClient {
	t.Helper()

	user := CreateVerifiedUser(t, name)
	ctx := context.Background()

	perms, err := user.Client.ListPermissions(ctx)
	require.NoError(t, err)

	var directPerms []sdk.DirectPermission
	for _, p := range perms.Permissions {
		directPerms = append(directPerms, sdk.DirectPermission{
			PermissionID: p.ID,
			Effect:       sdk.PermissionAllow,
		})
	}

	err = user.Client.SetDirectPermissions(ctx, sdk.SetDirectPermissionsRequest{
		UserID:      user.UserID,
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

// CreateUserInTenant creates a user in an existing tenant via gRPC, verifies email, and logs in
func CreateUserInTenant(t *testing.T, admin *UserClient, name string) *UserClient {
	t.Helper()
	return createUserInTenantWithRoles(t, admin, name, nil, true)
}

// CreateUserInTenantWithRoles creates a user with specific roles. NOT logged in (for MFA-required flows).
func CreateUserInTenantWithRoles(t *testing.T, admin *UserClient, name string, roleIDs []uuid.UUID) *UserClient {
	t.Helper()
	return createUserInTenantWithRoles(t, admin, name, roleIDs, false)
}

func createUserInTenantWithRoles(t *testing.T, admin *UserClient, name string, roleIDs []uuid.UUID, login bool) *UserClient {
	t.Helper()

	config := util.LoadConfig()
	email, password := GenerateTestCredentials(t, name)

	grpcClient, err := sdk.NewGRPCClient(config.HeimdallGRPCAddress)
	require.NoError(t, err)
	defer grpcClient.Close()

	ctx := identity.WithTenant(context.Background(), admin.TenantID)

	resp, err := grpcClient.CreateUser(ctx, sdk.CreateUserRequest{
		Email:   email,
		RoleIDs: roleIDs,
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.VerificationToken)

	client := CreateClient(t)

	_, err = client.VerifyEmail(context.Background(), sdk.VerifyEmailRequest{
		Token:    resp.VerificationToken,
		Password: password,
	})
	require.NoError(t, err)

	if login {
		_, err = client.Login(context.Background(), sdk.LoginRequest{
			Email:    email,
			Password: password,
		})
		require.NoError(t, err)
	}

	return &UserClient{
		Client:   client,
		UserID:   resp.UserID,
		TenantID: admin.TenantID,
		Email:    email,
		Password: password,
	}
}

// GetPermissionByName finds a permission by name from the permissions list
func GetPermissionByName(t *testing.T, client *sdk.HTTPClient, name string) sdk.Permission {
	t.Helper()

	resp, err := client.ListPermissions(context.Background())
	require.NoError(t, err)

	for _, p := range resp.Permissions {
		if p.Name == name {
			return p
		}
	}

	t.Fatalf("permission %q not found", name)
	return sdk.Permission{}
}

// GenerateTestCredentials generates unique email and password using nanosecond timestamps
func GenerateTestCredentials(t *testing.T, name string) (string, string) {
	t.Helper()

	ts := time.Now().UnixNano()
	email := fmt.Sprintf("%s-%d@test.example.com", name, ts)
	password := fmt.Sprintf("TestPass-%d!", ts)

	return email, password
}
