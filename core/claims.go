// Package core provides the core types and interfaces for the fourauth authentication package.
//
// This package includes token claims structures, configuration types, user/repository
// interfaces, and error definitions that are used by the authentication handlers.
//
// Example usage:
//
//	cfg := core.DefaultTokenConfig()
//	userRepo := &MyUserRepository{}
//	repo := core.NewRepository(userRepo, refreshTokenRepo)
package core

import "time"

// AccessClaims represents the claims stored in an access token.
// These claims are embedded in JWT or PASETO tokens to authenticate requests.
type AccessClaims struct {
	Subject   string
	Email     string
	Role      string
	ExpiresAt time.Time
}

// RefreshClaims represents the claims stored in a refresh token.
// Refresh tokens are used to obtain new access tokens without re-authenticating.
type RefreshClaims struct {
	Subject   string
	TokenID   string
	ExpiresAt time.Time
}
