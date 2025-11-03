package auth

import "errors"

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrAccountIsInactive = errors.New("user account is not active")
var ErrEmailNotVerified = errors.New("email address not verified")
var ErrDuplicateEmail = errors.New("email address is already registered")
