package sdk

import (
	"regexp"

	"github.com/google/uuid"
)

// emailRegex is a basic email validation pattern
// Matches standard email format: localpart@domain
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// User represents a user in API responses
type User struct {
	ID     uuid.UUID `json:"id"`
	Email  string    `json:"email"`
	Status string    `json:"status"`
}
