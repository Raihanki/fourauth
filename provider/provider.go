package provider

import (
	"context"

	"github.com/Raihanki/fourauth/core"
)

// PasswordProvider handles password hashing and comparison.
type PasswordProvider interface {
	// Hash returns a hash of the password.
	Hash(password string) (string, error)
	// Compare compares a password against a hash.
	Compare(hash, password string) error
}

// ExternalProvider handles OAuth2 authentication with external providers.
type ExternalProvider interface {
	// AuthCodeURL returns the OAuth2 authorization URL.
	AuthCodeURL(state string) string
	// Exchange exchanges an authorization code for user identity information.
	Exchange(ctx context.Context, code string) (core.ExternalIdentity, error)
	// UserFromGoogleToken retrieves user info from a Google access token.
	UserFromGoogleToken(ctx context.Context, accessToken string) (core.ExternalIdentity, error)
}
