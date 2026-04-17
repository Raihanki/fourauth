package token

import "github.com/Raihanki/fourauth/core"

// Issuer issues and parses access/refresh tokens.
// Use NewJWT or NewPaseto to create an Issuer.
type Issuer interface {
	// IssueAccessToken creates a new access token with the given claims.
	IssueAccessToken(claims core.AccessClaims) (core.Token, error)
	// IssueRefreshToken creates a new refresh token with the given claims.
	IssueRefreshToken(claims core.RefreshClaims) (core.Token, error)
	// ParseAccessToken validates and extracts claims from an access token.
	ParseAccessToken(raw string) (core.AccessClaims, error)
	// ParseRefreshToken validates and extracts claims from a refresh token.
	ParseRefreshToken(raw string) (core.RefreshClaims, error)
	// Kind returns the token kind (JWT or PASETO).
	Kind() core.TokenKind
}
