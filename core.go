package fourauth

import (
	"time"

	"github.com/Raihanki/fourauth/core"
)

func String(v string) *string {
	return &v
}

func NewToken(value string, expiredAt time.Time) Token {
	return Token{
		Value:     value,
		ExpiredAt: expiredAt,
	}
}

func NewTokenPair(accessToken, refreshToken Token) TokenPair {
	return TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
}

func NewAuthResult(user User, tokens TokenPair) AuthResult {
	return AuthResult{
		User:   user,
		Tokens: tokens,
	}
}

func NewExternalIdentity(
	provider string,
	providerID string,
	email string,
	name string,
	avatarURL string,
	emailVerified bool,
) ExternalIdentity {
	return ExternalIdentity{
		Provider:      provider,
		ProviderID:    providerID,
		Email:         email,
		Name:          name,
		AvatarURL:     avatarURL,
		EmailVerified: emailVerified,
	}
}

func NewLocalUserInput(email, name, passwordHash, role string) CreateUserInput {
	return CreateUserInput{
		Email:        email,
		Name:         name,
		Provider:     string(ProviderLocal),
		PasswordHash: String(passwordHash),
		Role:         role,
	}
}

func NewGoogleUserInput(
	email, name, providerID, avatarURL, role string,
	emailVerified bool,
) CreateUserInput {
	return CreateUserInput{
		Email:         email,
		Name:          name,
		Provider:      string(ProviderGoogle),
		ProviderID:    String(providerID),
		AvatarURL:     String(avatarURL),
		Role:          role,
		EmailVerified: emailVerified,
	}
}

func NewRefreshTokenRecord(
	tokenID string,
	userID string,
	expiresAt time.Time,
	createdAt time.Time,
) RefreshTokenRecord {
	return RefreshTokenRecord{
		TokenID:   tokenID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: createdAt,
	}
}

func DefaultTokenConfig() TokenConfig {
	return core.DefaultTokenConfig()
}

func DefaultCookieConfig() CookieConfig {
	return core.DefaultCookieConfig()
}

func NewBearerConfig(refreshBodyField string) BearerConfig {
	return BearerConfig{
		RefreshBodyField: refreshBodyField,
	}
}

func NewGoogleConfig(clientID, clientSecret, redirectURL string) GoogleConfig {
	return GoogleConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
	}
}
