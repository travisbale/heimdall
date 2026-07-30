package iam_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/travisbale/heimdall/internal/iam"
)

func TestAllScopesAreNamespaced(t *testing.T) {
	t.Parallel()

	for _, scope := range iam.AllScopes {
		assert.True(t, strings.HasPrefix(string(scope), "heimdall:"),
			"scope %q must be namespaced so it cannot collide with a consuming service's permissions", scope)
	}
}

func TestAllScopesHasNoDuplicates(t *testing.T) {
	t.Parallel()

	seen := make(map[iam.Scope]bool, len(iam.AllScopes))
	for _, scope := range iam.AllScopes {
		assert.False(t, seen[scope], "scope %q is listed twice in AllScopes", scope)
		seen[scope] = true
	}
}
