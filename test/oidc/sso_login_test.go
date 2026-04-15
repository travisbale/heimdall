package oidc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestSSOLoginValidation(t *testing.T) {
	t.Parallel()
	client := setup.CreateClient(t)
	ctx := context.Background()

	t.Run("unconfigured domain returns error", func(t *testing.T) {
		_, err := client.SSOLogin(ctx, sdk.SSOLoginRequest{
			Email: "user@unconfigured-domain.com",
		})
		assert.Error(t, err, "unconfigured domain should return error")
	})
}
