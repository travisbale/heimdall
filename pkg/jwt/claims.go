package jwt

import (
	"errors"
	"slices"

	jwt "github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	jwt.RegisteredClaims
	CSRF        string   `json:"csrf"`
	Type        string   `json:"type"`
	Permissions []string `json:"permissions,omitempty"`
}

func (c *Claims) HasPermission(permission string) error {
	if slices.Contains(c.Permissions, permission) {
		return nil
	}

	return errors.New("missing permission")
}
