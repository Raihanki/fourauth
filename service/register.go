package service

import (
	"context"

	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/model"
)

// RegisterInput contains the data needed to register a new local user.
type RegisterInput struct {
	Email    string
	Password string
	Name     string
	Role     string
}

// Register creates a new user account with email and password.
// Returns ErrEmailCollision if the email is already registered.
func (s *Service) Register(ctx context.Context, in RegisterInput) (core.AuthResult, error) {
	_, err := s.repo.GetByEmail(ctx, in.Email)
	if err == nil {
		return core.AuthResult{}, core.ErrEmailCollision
	}

	hash, err := s.localHash(in.Password)
	if err != nil {
		return core.AuthResult{}, err
	}

	user, err := s.repo.Create(ctx, &model.BaseUserInput{
		Email:         in.Email,
		PasswordHash:  &hash,
		Provider:      string(core.ProviderLocal),
		Name:          in.Name,
		Role:          in.Role,
		EmailVerified: false,
	})
	if err != nil {
		return core.AuthResult{}, err
	}

	pair, err := s.IssueTokenPair(user)
	if err != nil {
		return core.AuthResult{}, err
	}

	return core.AuthResult{User: user, Tokens: pair}, nil
}

func (s *Service) localHash(password string) (string, error) {
	return s.local.Hash(password)
}
