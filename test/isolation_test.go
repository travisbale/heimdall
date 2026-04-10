//go:build integration

package test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
)

func TestTenantIsolation_Roles(t *testing.T) {
	t.Parallel()
	// Two admin users in separate tenants
	tenantA := CreateAdminUser(t, "iso-roles-a")
	tenantB := CreateAdminUser(t, "iso-roles-b")
	ctx := context.Background()

	// Create a role in tenant A
	roleA, err := tenantA.Client.CreateRole(ctx, sdk.CreateRoleRequest{
		Name:        "Tenant A Role",
		Description: "Belongs to tenant A",
	})
	require.NoError(t, err)

	t.Run("tenant B cannot see tenant A roles", func(t *testing.T) {
		roles, err := tenantB.Client.ListRoles(ctx)
		require.NoError(t, err)

		for _, r := range roles.Roles {
			assert.NotEqual(t, roleA.ID, r.ID, "tenant B should not see tenant A roles")
		}
	})

	t.Run("tenant B cannot get tenant A role by ID", func(t *testing.T) {
		_, err := tenantB.Client.GetRole(ctx, sdk.GetRoleRequest{RoleID: roleA.ID})
		assert.Error(t, err, "tenant B should not access tenant A role")
	})

	t.Run("tenant B delete of tenant A role is a no-op", func(t *testing.T) {
		// RLS filters the DELETE to 0 rows — no error, but nothing is deleted
		err := tenantB.Client.DeleteRole(ctx, sdk.DeleteRoleRequest{RoleID: roleA.ID})
		require.NoError(t, err)

		// Verify tenant A role still exists
		role, err := tenantA.Client.GetRole(ctx, sdk.GetRoleRequest{RoleID: roleA.ID})
		require.NoError(t, err)
		assert.Equal(t, roleA.ID, role.ID, "tenant A role should still exist")
	})
}

func TestTenantIsolation_UserRoles(t *testing.T) {
	t.Parallel()
	tenantA := CreateAdminUser(t, "iso-userroles-a")
	tenantB := CreateAdminUser(t, "iso-userroles-b")
	ctx := context.Background()

	// Create a user in tenant A
	userA := CreateUserInTenant(t, tenantA, "iso-target-a")
	userAID := GetUserID(t, userA.Email)

	// Create a role in tenant A
	roleA, err := tenantA.Client.CreateRole(ctx, sdk.CreateRoleRequest{
		Name:        "Tenant A Assignment Role",
		Description: "For cross-tenant assignment test",
	})
	require.NoError(t, err)

	// Assign role in tenant A
	err = tenantA.Client.SetUserRoles(ctx, sdk.SetUserRolesRequest{
		UserID:  userAID,
		RoleIDs: []uuid.UUID{roleA.ID},
	})
	require.NoError(t, err)

	t.Run("tenant B sees empty roles for tenant A user", func(t *testing.T) {
		// RLS filters the user — returns empty result, not an error
		roles, err := tenantB.Client.GetUserRoles(ctx, sdk.GetUserRolesRequest{UserID: userAID})
		require.NoError(t, err)
		assert.Empty(t, roles.Roles, "tenant B should see no roles for tenant A user")
	})

	t.Run("tenant B role assignment to tenant A user is a no-op", func(t *testing.T) {
		// RLS prevents cross-tenant modification — silent no-op
		err := tenantB.Client.SetUserRoles(ctx, sdk.SetUserRolesRequest{
			UserID:  userAID,
			RoleIDs: []uuid.UUID{},
		})
		require.NoError(t, err)

		// Verify tenant A user still has their role
		roles, err := tenantA.Client.GetUserRoles(ctx, sdk.GetUserRolesRequest{UserID: userAID})
		require.NoError(t, err)
		assert.Len(t, roles.Roles, 1, "tenant A user should still have their role")
	})
}

func TestTenantIsolation_Permissions(t *testing.T) {
	t.Parallel()
	tenantA := CreateAdminUser(t, "iso-perms-a")
	tenantB := CreateAdminUser(t, "iso-perms-b")
	ctx := context.Background()

	t.Run("permissions are global across tenants", func(t *testing.T) {
		permsA, err := tenantA.Client.ListPermissions(ctx)
		require.NoError(t, err)

		permsB, err := tenantB.Client.ListPermissions(ctx)
		require.NoError(t, err)

		// Both tenants should see the same system permissions
		assert.Equal(t, len(permsA.Permissions), len(permsB.Permissions),
			"both tenants should see the same number of permissions")
	})
}

func TestTenantIsolation_Sessions(t *testing.T) {
	t.Parallel()
	tenantA := CreateVerifiedUser(t, "iso-sessions-a")
	tenantB := CreateVerifiedUser(t, "iso-sessions-b")
	ctx := context.Background()

	t.Run("tenant B cannot see tenant A sessions", func(t *testing.T) {
		sessionsA, err := tenantA.Client.ListSessions(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, sessionsA.Sessions)

		sessionsB, err := tenantB.Client.ListSessions(ctx)
		require.NoError(t, err)

		// Tenant B's sessions should not contain tenant A's session IDs
		aIDs := make(map[uuid.UUID]bool)
		for _, s := range sessionsA.Sessions {
			aIDs[s.ID] = true
		}
		for _, s := range sessionsB.Sessions {
			assert.False(t, aIDs[s.ID], "tenant B should not see tenant A sessions")
		}
	})

	t.Run("tenant B cannot revoke tenant A session", func(t *testing.T) {
		sessionsA, err := tenantA.Client.ListSessions(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, sessionsA.Sessions)

		err = tenantB.Client.RevokeSession(ctx, sdk.RevokeSessionRequest{
			SessionID: sessionsA.Sessions[0].ID,
		})
		assert.Error(t, err, "tenant B should not revoke tenant A session")
	})
}

func TestTenantIsolation_OIDCProviders(t *testing.T) {
	t.Parallel()
	tenantA := CreateAdminUser(t, "iso-oidc-a")
	tenantB := CreateAdminUser(t, "iso-oidc-b")
	ctx := context.Background()

	// Create OIDC provider in tenant A
	providerA, err := tenantA.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
		ProviderName:   "Tenant A Provider",
		IssuerURL:      harness.OIDCMockURL + "/default",
		ClientID:       "tenant-a-client",
		ClientSecret:   "tenant-a-secret",
		AllowedDomains: []string{"tenanta.com"},
		Enabled:        true,
	})
	require.NoError(t, err)

	t.Run("tenant B cannot see tenant A providers", func(t *testing.T) {
		providers, err := tenantB.Client.ListOIDCProviders(ctx)
		require.NoError(t, err)

		for _, p := range providers.Providers {
			assert.NotEqual(t, providerA.ID, p.ID, "tenant B should not see tenant A providers")
		}
	})

	t.Run("tenant B cannot get tenant A provider by ID", func(t *testing.T) {
		_, err := tenantB.Client.GetOIDCProvider(ctx, sdk.GetOIDCProviderRequest{
			ProviderID: providerA.ID,
		})
		assert.Error(t, err)
	})

	t.Run("tenant B delete of tenant A provider has no effect", func(t *testing.T) {
		// Delete may return error or silently no-op depending on RLS behavior
		_ = tenantB.Client.DeleteOIDCProvider(ctx, sdk.DeleteOIDCProviderRequest{
			ProviderID: providerA.ID,
		})

		// Verify tenant A provider still exists regardless
		provider, err := tenantA.Client.GetOIDCProvider(ctx, sdk.GetOIDCProviderRequest{
			ProviderID: providerA.ID,
		})
		require.NoError(t, err)
		assert.Equal(t, providerA.ID, provider.ID)
	})
}

func TestTenantIsolation_Users(t *testing.T) {
	t.Parallel()
	tenantA := CreateVerifiedUser(t, "iso-users-a")
	tenantB := CreateVerifiedUser(t, "iso-users-b")
	ctx := context.Background()

	t.Run("tenant A user profile is isolated", func(t *testing.T) {
		meA, err := tenantA.Client.GetMe(ctx)
		require.NoError(t, err)

		meB, err := tenantB.Client.GetMe(ctx)
		require.NoError(t, err)

		// Each user sees only their own profile
		assert.Equal(t, tenantA.Email, meA.Email)
		assert.Equal(t, tenantB.Email, meB.Email)
		assert.NotEqual(t, meA.TenantID, meB.TenantID, "users should be in different tenants")
	})
}

func TestTenantIsolation_RolePermissions(t *testing.T) {
	t.Parallel()
	tenantA := CreateAdminUser(t, "iso-roleperms-a")
	tenantB := CreateAdminUser(t, "iso-roleperms-b")
	ctx := context.Background()

	// Create a role with permissions in tenant A
	roleA, err := tenantA.Client.CreateRole(ctx, sdk.CreateRoleRequest{
		Name: "Role With Perms", Description: "Has permissions",
	})
	require.NoError(t, err)

	perm := GetPermissionByName(t, tenantA.Client, "role:read")
	err = tenantA.Client.SetRolePermissions(ctx, sdk.SetRolePermissionsRequest{
		RoleID: roleA.ID, PermissionIDs: []uuid.UUID{perm.ID},
	})
	require.NoError(t, err)

	t.Run("tenant B cannot get tenant A role permissions", func(t *testing.T) {
		perms, err := tenantB.Client.GetRolePermissions(ctx, sdk.GetRolePermissionsRequest{
			RoleID: roleA.ID,
		})
		// RLS returns empty — role not visible to tenant B
		require.NoError(t, err)
		assert.Empty(t, perms.Permissions)
	})

	t.Run("tenant B cannot set tenant A role permissions", func(t *testing.T) {
		err := tenantB.Client.SetRolePermissions(ctx, sdk.SetRolePermissionsRequest{
			RoleID:        roleA.ID,
			PermissionIDs: []uuid.UUID{},
		})
		// Silent no-op via RLS
		require.NoError(t, err)

		// Tenant A permissions unchanged
		perms, err := tenantA.Client.GetRolePermissions(ctx, sdk.GetRolePermissionsRequest{
			RoleID: roleA.ID,
		})
		require.NoError(t, err)
		assert.Len(t, perms.Permissions, 1)
	})
}

func TestTenantIsolation_UserPermissions(t *testing.T) {
	t.Parallel()
	tenantA := CreateAdminUser(t, "iso-userperms-a")
	tenantB := CreateAdminUser(t, "iso-userperms-b")
	ctx := context.Background()

	userA := CreateUserInTenant(t, tenantA, "iso-permtarget-a")
	userAID := GetUserID(t, userA.Email)

	perm := GetPermissionByName(t, tenantA.Client, "role:read")
	err := tenantA.Client.SetDirectPermissions(ctx, sdk.SetDirectPermissionsRequest{
		UserID: userAID,
		Permissions: []sdk.DirectPermission{
			{PermissionID: perm.ID, Effect: sdk.PermissionAllow},
		},
	})
	require.NoError(t, err)

	t.Run("tenant B cannot get tenant A user permissions", func(t *testing.T) {
		perms, err := tenantB.Client.GetDirectPermissions(ctx, sdk.GetDirectPermissionsRequest{
			UserID: userAID,
		})
		require.NoError(t, err)
		assert.Empty(t, perms.Permissions, "tenant B should see no permissions for tenant A user")
	})

	t.Run("tenant B cannot set tenant A user permissions", func(t *testing.T) {
		err := tenantB.Client.SetDirectPermissions(ctx, sdk.SetDirectPermissionsRequest{
			UserID:      userAID,
			Permissions: []sdk.DirectPermission{},
		})
		require.NoError(t, err)

		// Tenant A permissions unchanged
		perms, err := tenantA.Client.GetDirectPermissions(ctx, sdk.GetDirectPermissionsRequest{
			UserID: userAID,
		})
		require.NoError(t, err)
		assert.Len(t, perms.Permissions, 1)
	})
}

func TestTenantIsolation_OIDCLinks(t *testing.T) {
	t.Parallel()
	tenantA := CreateAdminUser(t, "iso-links-a")
	tenantB := CreateAdminUser(t, "iso-links-b")
	ctx := context.Background()

	// Each tenant creates their own OIDC provider
	providerA, err := tenantA.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
		ProviderName:    "Tenant A Azure",
		IssuerURL:       harness.OIDCMockURL + "/default",
		ClientID:        "a-azure-client",
		ClientSecret:    "a-azure-secret",
		AllowedDomains:  []string{"companya.com"},
		Enabled:         true,
		AutoCreateUsers: true,
	})
	require.NoError(t, err)

	providerB, err := tenantB.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
		ProviderName:    "Tenant B Azure",
		IssuerURL:       harness.OIDCMockURL + "/default",
		ClientID:        "b-azure-client",
		ClientSecret:    "b-azure-secret",
		AllowedDomains:  []string{"companyb.com"},
		Enabled:         true,
		AutoCreateUsers: true,
	})
	require.NoError(t, err)

	t.Run("OIDC links isolated via provider foreign keys", func(t *testing.T) {
		// Each tenant can only see their own provider
		respA, err := tenantA.Client.ListOIDCProviders(ctx)
		require.NoError(t, err)
		require.Len(t, respA.Providers, 1)
		assert.Equal(t, providerA.ID, respA.Providers[0].ID)

		respB, err := tenantB.Client.ListOIDCProviders(ctx)
		require.NoError(t, err)
		require.Len(t, respB.Providers, 1)
		assert.Equal(t, providerB.ID, respB.Providers[0].ID)
	})

	t.Run("cross-tenant provider not visible", func(t *testing.T) {
		providersA, err := tenantA.Client.ListOIDCProviders(ctx)
		require.NoError(t, err)
		for _, p := range providersA.Providers {
			assert.NotEqual(t, providerB.ID, p.ID, "tenant A should not see tenant B provider")
		}

		providersB, err := tenantB.Client.ListOIDCProviders(ctx)
		require.NoError(t, err)
		for _, p := range providersB.Providers {
			assert.NotEqual(t, providerA.ID, p.ID, "tenant B should not see tenant A provider")
		}
	})
}

func TestTenantIsolation_SSODiscovery(t *testing.T) {
	t.Parallel()
	tenantA := CreateAdminUser(t, "iso-sso-a")
	tenantB := CreateAdminUser(t, "iso-sso-b")
	ctx := context.Background()

	// Both tenants configure SSO for different domains
	_, err := tenantA.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
		ProviderName:    "Tenant A SSO",
		IssuerURL:       harness.OIDCMockURL + "/default",
		ClientID:        "a-client",
		ClientSecret:    "a-secret",
		AllowedDomains:  []string{"tenanta-sso.com"},
		Enabled:         true,
		AutoCreateUsers: true,
	})
	require.NoError(t, err)

	_, err = tenantB.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
		ProviderName:    "Tenant B SSO",
		IssuerURL:       harness.OIDCMockURL + "/default",
		ClientID:        "b-client",
		ClientSecret:    "b-secret",
		AllowedDomains:  []string{"tenantb-sso.com"},
		Enabled:         true,
		AutoCreateUsers: true,
	})
	require.NoError(t, err)

	t.Run("SSO discovers correct tenant provider", func(t *testing.T) {
		// Tenant A's domain should work
		resp, err := tenantA.Client.SSOLogin(ctx, sdk.SSOLoginRequest{
			Email: "user@tenanta-sso.com",
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AuthorizationURL)
	})

	t.Run("SSO for unconfigured domain fails", func(t *testing.T) {
		_, err := tenantA.Client.SSOLogin(ctx, sdk.SSOLoginRequest{
			Email: "user@no-sso-configured.com",
		})
		assert.Error(t, err, "unconfigured domain should fail")
	})
}
