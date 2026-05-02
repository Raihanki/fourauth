package service

import (
	"context"

	"github.com/Raihanki/fourauth/core"
)

// LoginLocal authenticates a user with email and password.
// Returns ErrInvalidCreds if authentication fails.
func (s *Service) LoginLocal(ctx context.Context, email, password string) (core.AuthResult, error) {
	user, err := s.repo.GetByEmail(ctx, email)
	if err != nil {
		return core.AuthResult{}, core.ErrInvalidCreds
	}

	hash := user.GetPasswordHash()
	if hash == nil || *hash == "" {
		return core.AuthResult{}, core.ErrInvalidCreds
	}

	if err := s.localCompare(*hash, password); err != nil {
		return core.AuthResult{}, core.ErrInvalidCreds
	}

	pair, err := s.IssueTokenPair(user)
	if err != nil {
		return core.AuthResult{}, err
	}

	return core.AuthResult{User: user, Tokens: pair}, nil
}

func (s *Service) localCompare(hash, password string) error {
	return s.local.Compare(hash, password)
}
