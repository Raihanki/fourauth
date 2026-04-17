package mocks

import (
	"context"

	"github.com/Raihanki/fourauth/core"
	"github.com/stretchr/testify/mock"
)

type RefreshTokenRepository struct {
	mock.Mock
}

func (m *RefreshTokenRepository) Save(ctx context.Context, token core.RefreshTokenRecord) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *RefreshTokenRepository) Find(ctx context.Context, tokenID string) (core.RefreshTokenRecord, error) {
	args := m.Called(ctx, tokenID)

	record, _ := args.Get(0).(core.RefreshTokenRecord)
	return record, args.Error(1)
}

func (m *RefreshTokenRepository) Revoke(ctx context.Context, tokenID string) error {
	args := m.Called(ctx, tokenID)
	return args.Error(0)
}
