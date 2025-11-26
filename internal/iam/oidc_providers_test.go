package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestOIDCProviderCRUD(t *testing.T) {
	t.Run("Create", func(t *testing.T) {
		f := newTestFixture(nil, nil)
		tenantID := uuid.New()
		provider := testProviderConfig(tenantID, "newdomain.com")
		provider.ProviderName = "New Provider"

		result, err := f.providerService.CreateOIDCProvider(context.Background(), provider, "")
		if err != nil {
			t.Fatalf("CreateOIDCProvider failed: %v", err)
		}
		if result.ID == uuid.Nil {
			t.Error("provider should have an ID")
		}
		if result.ProviderName != "New Provider" {
			t.Errorf("expected provider name 'New Provider', got %s", result.ProviderName)
		}
	})

	t.Run("Get", func(t *testing.T) {
		f := newTestFixture(nil, nil)
		tenantID := uuid.New()
		provider := testProviderConfig(tenantID, "test.com")
		provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

		result, err := f.providerService.GetOIDCProvider(context.Background(), provider.ID)
		if err != nil {
			t.Fatalf("GetOIDCProvider failed: %v", err)
		}
		if result.ID != provider.ID {
			t.Error("should return the correct provider")
		}
	})

	t.Run("GetNotFound", func(t *testing.T) {
		f := newTestFixture(nil, nil)

		_, err := f.providerService.GetOIDCProvider(context.Background(), uuid.New())
		if !errors.Is(err, ErrOIDCProviderNotFound) {
			t.Errorf("expected ErrOIDCProviderNotFound, got: %v", err)
		}
	})

	t.Run("Update", func(t *testing.T) {
		f := newTestFixture(nil, nil)
		tenantID := uuid.New()
		provider := testProviderConfig(tenantID, "test.com")
		provider.ProviderName = "Original Name"
		provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

		newName := "Updated Name"
		params := &UpdateOIDCProviderParams{
			ID:           provider.ID,
			ProviderName: &newName,
		}

		result, err := f.providerService.UpdateOIDCProvider(context.Background(), params)
		if err != nil {
			t.Fatalf("UpdateOIDCProvider failed: %v", err)
		}
		if result.ProviderName != "Updated Name" {
			t.Errorf("expected provider name 'Updated Name', got %s", result.ProviderName)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		f := newTestFixture(nil, nil)
		tenantID := uuid.New()
		provider := testProviderConfig(tenantID, "test.com")
		provider, _ = f.providerDB.CreateOIDCProvider(context.Background(), provider)

		err := f.providerService.DeleteOIDCProvider(context.Background(), provider.ID)
		if err != nil {
			t.Fatalf("DeleteOIDCProvider failed: %v", err)
		}

		_, err = f.providerService.GetOIDCProvider(context.Background(), provider.ID)
		if !errors.Is(err, ErrOIDCProviderNotFound) {
			t.Error("provider should be deleted")
		}
	})

	t.Run("List", func(t *testing.T) {
		f := newTestFixture(nil, nil)
		tenantID := uuid.New()

		for i := 0; i < 3; i++ {
			provider := testProviderConfig(tenantID, "test.com")
			f.providerDB.CreateOIDCProvider(context.Background(), provider)
		}

		providers, err := f.providerService.ListOIDCProviders(context.Background())
		if err != nil {
			t.Fatalf("ListOIDCProviders failed: %v", err)
		}
		if len(providers) != 3 {
			t.Errorf("expected 3 providers, got %d", len(providers))
		}
	})
}

// Multi-tenancy Edge Cases
