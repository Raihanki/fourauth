package core

import "time"

// ProviderName represents the authentication provider type.
type ProviderName string

const (
	ProviderLocal  ProviderName = "local"
	ProviderGoogle ProviderName = "google"
)

// TokenKind represents the token format type.
type TokenKind string

const (
	TokenKindJWT    TokenKind = "jwt"
	TokenKindPaseto TokenKind = "paseto"
)

// TransportKind represents the method used to transport tokens.
type TransportKind string

const (
	TransportKindCookie TransportKind = "cookie"
	TransportKindBearer TransportKind = "bearer"
)

// Token represents a single token with expiration.
type Token struct {
	Value     string
	ExpiredAt time.Time
}

// TokenPair contains both access and refresh tokens.
type TokenPair struct {
	AccessToken  Token
	RefreshToken Token
}

// AuthResult contains the authenticated user and token pair.
type AuthResult struct {
	User   User
	Tokens TokenPair
}

// ExternalIdentity represents a user's identity from an external OAuth provider.
type ExternalIdentity struct {
	Provider      string
	ProviderID    string
	Email         string
	Name          string
	AvatarURL     string
	EmailVerified bool
}

// CreateUserInput contains the data needed to create a new user.
type CreateUserInput struct {
	Email         string
	PasswordHash  *string
	Provider      string
	ProviderID    *string
	Name          string
	AvatarURL     *string
	Role          string
	EmailVerified bool
}

// RefreshTokenRecord represents a stored refresh token in the database.
type RefreshTokenRecord struct {
	TokenID   string
	UserID    string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}
