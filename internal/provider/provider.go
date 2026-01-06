package provider

import "errors"

var (
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")
	ErrMissingData  = errors.New("missing email or password")
)
