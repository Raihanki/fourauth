package core

import "errors"

// ErrUnauthorized is returned when a request is not authenticated.
var ErrUnauthorized = errors.New("unauthorized")

// ErrInvalidToken is returned when a token is malformed, expired, or has invalid signature.
var ErrInvalidToken = errors.New("invalid token")

// ErrInvalidState is returned when OAuth state parameter is invalid or missing.
var ErrInvalidState = errors.New("invalid oauth state")

// ErrInvalidCreds is returned when provided credentials are incorrect.
var ErrInvalidCreds = errors.New("invalid credentials")

// ErrUserNotFound is returned when a user cannot be found by ID or email.
var ErrUserNotFound = errors.New("user not found")

// ErrEmailCollision is returned when an email is already registered with a different auth provider.
var ErrEmailCollision = errors.New("email already registered with another auth method")

// ErrCSRFTokenMissing is returned when CSRF token is not present in request.
var ErrCSRFTokenMissing = errors.New("csrf token missing")

// ErrCSRFTokenInvalid is returned when CSRF token does not match.
var ErrCSRFTokenInvalid = errors.New("csrf token invalid")

// ErrMissingCookieToken is returned when expected cookie token is not found.
var ErrMissingCookieToken = errors.New("missing cookie token")

// ErrStateMissing is returned when OAuth state parameter is not present.
var ErrStateMissing = errors.New("missing state")

// ErrStateInvalid is returned when OAuth state parameter is corrupted or tampered.
var ErrStateInvalid = errors.New("invalid state")

// ErrUnsupportedWriteTokens is returned when token transport does not support writing tokens.
var ErrUnsupportedWriteTokens = errors.New("transport does not support writing tokens")

// ErrUnsupportedRefreshRead is returned when token transport does not support reading refresh tokens.
var ErrUnsupportedRefreshRead = errors.New("transport does not support reading refresh token")

// ErrUnsupportedClear is returned when token transport does not support clearing state.
var ErrUnsupportedClear = errors.New("transport does not support clearing state")

// ErrMissingAuthorizationHeader is returned when Authorization header is expected but missing.
var ErrMissingAuthorizationHeader = errors.New("missing authorization header")
