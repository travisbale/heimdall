package auth

import "errors"

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrUserNotFound = errors.New("user not found")
var ErrAccountIsInactive = errors.New("user account is not active")
var ErrEmailNotVerified = errors.New("email address not verified")
var ErrDuplicateEmail = errors.New("email address is already registered")
var ErrAccountLocked = errors.New("account is temporarily locked due to too many failed login attempts")
