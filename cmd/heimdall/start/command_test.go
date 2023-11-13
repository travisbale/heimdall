package start

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigureServer(t *testing.T) {
	server, err := configureServer("localhost", 8080)

	assert.Equal(t, server.Addr, "localhost:8080")
	assert.Nil(t, err)
}
