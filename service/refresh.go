package service

import (
	"context"

	"github.com/Raihanki/fourauth/core"
)

// Refresh exchanges a refresh token for a new token pair.
// Validates the refresh token and issues new access/refresh tokens for the user.
func (s *Service) Refresh(ctx context.Context, rawRefresh string) (core.TokenPair, error) {
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
