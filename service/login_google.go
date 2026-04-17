package service

import (
	"context"

	"github.com/Raihanki/fourauth/core"
)

// GoogleAuthURL returns the Google OAuth2 authorization URL.
// The state parameter is used to validate the callback request.
func (s *Service) GoogleAuthURL(state string) (string, string, error) {
	return s.google.AuthCodeURL(state), state, nil
}

// LoginGoogleCallback exchanges an OAuth authorization code for user tokens.
// Creates a new user if this is their first Google login.
// Returns ErrEmailCollision if the email is already registered with a different provider.
func (s *Service) LoginGoogleCallback(ctx context.Context, code string) (core.AuthResult, error) {
	identity, err := s.google.Exchange(ctx, code)
	if err != nil {
		return core.AuthResult{}, err
	}

	user, err := s.repo.GetByProvider(ctx, identity.Provider, identity.ProviderID)
	if err == nil {
		pair, err := s.issueTokenPair(user)
		if err != nil {
			return core.AuthResult{}, err
		}
		return core.AuthResult{User: user, Tokens: pair}, nil
	}

	_, err = s.repo.GetByEmail(ctx, identity.Email)
	if err == nil {
		return core.AuthResult{}, core.ErrEmailCollision
	}

	avatar := identity.AvatarURL
	providerID := identity.ProviderID
	user, err = s.repo.Create(ctx, core.CreateUserInput{
		Email:         identity.Email,
		PasswordHash:  nil,
		Provider:      identity.Provider,
		ProviderID:    &providerID,
		Name:          identity.Name,
		AvatarURL:     &avatar,
		Role:          "user",
		EmailVerified: identity.EmailVerified,
	})
	if err != nil {
		return core.AuthResult{}, err
	}

	pair, err := s.issueTokenPair(user)
	if err != nil {
		return core.AuthResult{}, err
	}

	return core.AuthResult{User: user, Tokens: pair}, nil
}

// UserFromToken authenticates a user from a Google ID token.
// Used for Google sign-in on mobile or single-page applications.
func (s *Service) UserFromToken(ctx context.Context, token string) (core.AuthResult, error) {
	identity, err := s.google.UserFromGoogleToken(ctx, token)
	if err != nil {
		return core.AuthResult{}, err
	}

	user, err := s.repo.GetByProvider(ctx, identity.Provider, identity.ProviderID)
	if err == nil {
		pair, err := s.issueTokenPair(user)
		if err != nil {
			return core.AuthResult{}, err
		}
		return core.AuthResult{User: user, Tokens: pair}, nil
	}

	_, err = s.repo.GetByEmail(ctx, identity.Email)
	if err == nil {
		return core.AuthResult{}, core.ErrEmailCollision
	}

	avatar := identity.AvatarURL
	providerID := identity.ProviderID
	user, err = s.repo.Create(ctx, core.CreateUserInput{
		Email:         identity.Email,
		PasswordHash:  nil,
		Provider:      identity.Provider,
		ProviderID:    &providerID,
		Name:          identity.Name,
		AvatarURL:     &avatar,
		Role:          "user",
		EmailVerified: identity.EmailVerified,
	})
	if err != nil {
		return core.AuthResult{}, err
	}

	pair, err := s.issueTokenPair(user)
	if err != nil {
		return core.AuthResult{}, err
	}

	return core.AuthResult{User: user, Tokens: pair}, nil
}
