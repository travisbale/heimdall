package start

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigureServer(t *testing.T) {
	server, err := configureServer(context.Background(), "localhost", 8080, "")

	assert.Equal(t, server.Addr, "localhost:8080")
	assert.Nil(t, err)
}
