package iam

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// Test Helpers

type rbacTestFixture struct {
	roleRepo     *mockRoleRepository
	permRepo     *mockPermissionRepository
	rolePermRepo *mockRolePermissionRepository
	userRoleRepo *mockUserRoleRepository
	userPermRepo *mockUserPermissionRepository
	service      *RBACService
}

func newRBACTestFixture() *rbacTestFixture {
	roleRepo := newMockRoleRepository()
	permRepo := newMockPermissionRepository()
	rolePermRepo := &mockRolePermissionRepository{}
	userRoleRepo := &mockUserRoleRepository{}
	userPermRepo := &mockUserPermissionRepository{}

	service := NewRBACService(&RBACServiceConfig{
		RolesDB:           roleRepo,
		PermissionsDB:     permRepo,
		RolePermissionsDB: rolePermRepo,
		UserRolesDB:       userRoleRepo,
		UserPermissionsDB: userPermRepo,
		Logger:            &mockLogger{},
	})

	return &rbacTestFixture{
		roleRepo:     roleRepo,
		permRepo:     permRepo,
		rolePermRepo: rolePermRepo,
		userRoleRepo: userRoleRepo,
		userPermRepo: userPermRepo,
		service:      service,
	}
}

// Test GetUserScopes - Deny removes permissions
func TestGetUserScopes_DenyRemovesPermission(t *testing.T) {
	permRepo := newMockPermissionRepository()
	userID := uuid.New()

	// User has role-based allow for users:read, but direct deny
	permRepo.userPermissions[userID] = []*EffectivePermission{
		{
			Permission: &Permission{
				ID:          uuid.New(),
				Name:        "users:read",
				Description: "Read users",
			},
			Effect: "allow",
		},
		{
			Permission: &Permission{
				ID:          uuid.New(),
				Name:        "users:write",
				Description: "Write users",
			},
			Effect: "allow",
		},
		{
			Permission: &Permission{
				ID:          uuid.New(),
				Name:        "users:read",
				Description: "Read users",
			},
			Effect: "deny",
		},
	}

	service := NewRBACService(&RBACServiceConfig{
		RolesDB:           newMockRoleRepository(),
		PermissionsDB:     permRepo,
		RolePermissionsDB: &mockRolePermissionRepository{},
		UserRolesDB:       &mockUserRoleRepository{},
		UserPermissionsDB: &mockUserPermissionRepository{},
		Logger:            &mockLogger{},
	})

	permissions, err := service.GetUserScopes(context.Background(), userID)
	if err != nil {
		t.Fatalf("GetUserScopes failed: %v", err)
	}

	// Should only have users:write (users:read was denied)
	if len(permissions) != 1 {
		t.Errorf("Expected 1 permission, got %d", len(permissions))
	}

	if len(permissions) > 0 && permissions[0] != "users:write" {
		t.Errorf("Expected users:write, got %s", permissions[0])
	}
}

// Test GetUserScopes - Multiple allows deduplicated
func TestGetUserScopes_MultipleAllowsDeduplicated(t *testing.T) {
	permRepo := newMockPermissionRepository()
	userID := uuid.New()

	// User has same permission from multiple sources (role + direct)
	permRepo.userPermissions[userID] = []*EffectivePermission{
		{
			Permission: &Permission{
				ID:          uuid.New(),
				Name:        "users:read",
				Description: "Read users",
			},
			Effect: "allow",
		},
		{
			Permission: &Permission{
				ID:          uuid.New(),
				Name:        "users:read",
				Description: "Read users",
			},
			Effect: "allow",
		},
		{
			Permission: &Permission{
				ID:          uuid.New(),
				Name:        "users:write",
				Description: "Write users",
			},
			Effect: "allow",
		},
	}

	service := NewRBACService(&RBACServiceConfig{
		RolesDB:           newMockRoleRepository(),
		PermissionsDB:     permRepo,
		RolePermissionsDB: &mockRolePermissionRepository{},
		UserRolesDB:       &mockUserRoleRepository{},
		UserPermissionsDB: &mockUserPermissionRepository{},
		Logger:            &mockLogger{},
	})

	permissions, err := service.GetUserScopes(context.Background(), userID)
	if err != nil {
		t.Fatalf("GetUserScopes failed: %v", err)
	}

	// Should have 2 unique permissions
	if len(permissions) != 2 {
		t.Errorf("Expected 2 unique permissions, got %d", len(permissions))
	}

	// Check both permissions are present
	permMap := make(map[string]bool)
	for _, perm := range permissions {
		permMap[perm.String()] = true
	}

	if !permMap["users:read"] {
		t.Error("Expected users:read permission")
	}
	if !permMap["users:write"] {
		t.Error("Expected users:write permission")
	}
}

// Test GetUserScopes - Empty permissions
func TestGetUserScopes_EmptyPermissions(t *testing.T) {
	permRepo := newMockPermissionRepository()
	userID := uuid.New()

	permRepo.userPermissions[userID] = []*EffectivePermission{}

	service := NewRBACService(&RBACServiceConfig{
		RolesDB:           newMockRoleRepository(),
		PermissionsDB:     permRepo,
		RolePermissionsDB: &mockRolePermissionRepository{},
		UserRolesDB:       &mockUserRoleRepository{},
		UserPermissionsDB: &mockUserPermissionRepository{},
		Logger:            &mockLogger{},
	})

	permissions, err := service.GetUserScopes(context.Background(), userID)
	if err != nil {
		t.Fatalf("GetUserScopes failed: %v", err)
	}

	if len(permissions) != 0 {
		t.Errorf("Expected 0 permissions, got %d", len(permissions))
	}
}

// Test CreateRole
func TestRoleCRUD(t *testing.T) {
	t.Run("Create", func(t *testing.T) {
		f := newRBACTestFixture()

		role := &Role{
			Name:        "admin",
			Description: "Administrator role",
			MFARequired: false,
		}
		createdRole, err := f.service.CreateRole(context.Background(), role)
		if err != nil {
			t.Fatalf("CreateRole failed: %v", err)
		}
		if createdRole.Name != "admin" {
			t.Errorf("Expected role name 'admin', got '%s'", createdRole.Name)
		}
		if createdRole.Description != "Administrator role" {
			t.Errorf("Expected description 'Administrator role', got '%s'", createdRole.Description)
		}
	})

	t.Run("Get", func(t *testing.T) {
		f := newRBACTestFixture()
		roleID := uuid.New()
		f.roleRepo.roles[roleID] = &Role{
			ID:          roleID,
			Name:        "viewer",
			Description: "Read-only role",
			MFARequired: false,
		}

		role, err := f.service.GetRole(context.Background(), roleID)
		if err != nil {
			t.Fatalf("GetRole failed: %v", err)
		}
		if role.Name != "viewer" {
			t.Errorf("Expected role name 'viewer', got '%s'", role.Name)
		}
	})

	t.Run("GetNotFound", func(t *testing.T) {
		f := newRBACTestFixture()

		_, err := f.service.GetRole(context.Background(), uuid.New())
		if err != ErrRoleNotFound {
			t.Errorf("Expected ErrRoleNotFound, got %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		f := newRBACTestFixture()
		f.roleRepo.roles[uuid.New()] = &Role{
			ID:          uuid.New(),
			Name:        "admin",
			Description: "Admin role",
			MFARequired: true,
		}
		f.roleRepo.roles[uuid.New()] = &Role{
			ID:          uuid.New(),
			Name:        "viewer",
			Description: "Viewer role",
			MFARequired: false,
		}

		roles, err := f.service.ListRoles(context.Background())
		if err != nil {
			t.Fatalf("ListRoles failed: %v", err)
		}
		if len(roles) != 2 {
			t.Errorf("Expected 2 roles, got %d", len(roles))
		}
	})

	t.Run("Update", func(t *testing.T) {
		f := newRBACTestFixture()
		roleID := uuid.New()
		f.roleRepo.roles[roleID] = &Role{
			ID:          roleID,
			Name:        "editor",
			Description: "Editor role",
			MFARequired: false,
		}

		newName := "contributor"
		newDescription := "Contributor role"
		params := UpdateRoleParams{
			ID:          roleID,
			Name:        &newName,
			Description: &newDescription,
		}
		role, err := f.service.UpdateRole(context.Background(), params)
		if err != nil {
			t.Fatalf("UpdateRole failed: %v", err)
		}
		if role.Name != "contributor" {
			t.Errorf("Expected role name 'contributor', got '%s'", role.Name)
		}
		if role.Description != "Contributor role" {
			t.Errorf("Expected description 'Contributor role', got '%s'", role.Description)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		f := newRBACTestFixture()
		roleID := uuid.New()
		f.roleRepo.roles[roleID] = &Role{
			ID:          roleID,
			Name:        "temp",
			Description: "Temporary role",
			MFARequired: false,
		}

		err := f.service.DeleteRole(context.Background(), roleID)
		if err != nil {
			t.Fatalf("DeleteRole failed: %v", err)
		}

		_, exists := f.roleRepo.roles[roleID]
		if exists {
			t.Error("Expected role to be deleted")
		}
	})
}

// Test ListPermissions
func TestListPermissions_Success(t *testing.T) {
	permRepo := newMockPermissionRepository()
	perm1ID := uuid.New()
	perm2ID := uuid.New()

	permRepo.permissions[perm1ID] = &Permission{
		ID:          perm1ID,
		Name:        "users:read",
		Description: "Read users",
	}
	permRepo.permissions[perm2ID] = &Permission{
		ID:          perm2ID,
		Name:        "users:write",
		Description: "Write users",
	}

	service := NewRBACService(&RBACServiceConfig{
		RolesDB:           newMockRoleRepository(),
		PermissionsDB:     permRepo,
		RolePermissionsDB: &mockRolePermissionRepository{},
		UserRolesDB:       &mockUserRoleRepository{},
		UserPermissionsDB: &mockUserPermissionRepository{},
		Logger:            &mockLogger{},
	})

	permissions, err := service.ListPermissions(context.Background())
	if err != nil {
		t.Fatalf("ListPermissions failed: %v", err)
	}

	if len(permissions) != 2 {
		t.Errorf("Expected 2 permissions, got %d", len(permissions))
	}
}
