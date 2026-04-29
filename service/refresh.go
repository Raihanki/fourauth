package service

import (
	"context"

	"github.com/Raihanki/fourauth/core"
)

// Refresh exchanges a refresh token for a new token pair.
// Validates the refresh token and issues new access/refresh tokens for the user.
// Returns ErrRefreshTokenDisabled if refresh tokens are not enabled.
func (s *Service) Refresh(ctx context.Context, rawRefresh string) (core.TokenPair, error) {
	if !s.useRefreshToken {
		return core.TokenPair{}, core.ErrRefreshTokenDisabled
	}

	claims, err := s.issuer.ParseRefreshToken(rawRefresh)
	if err != nil {
		return core.TokenPair{}, core.ErrInvalidToken
	}

	user, err := s.repo.GetByID(ctx, claims.Subject)
	if err != nil {
		return core.TokenPair{}, core.ErrUnauthorized
	}

	return s.issueTokenPair(user)
}
