package mocks

import (
	"context"

	"github.com/Raihanki/fourauth/core"
	"github.com/stretchr/testify/mock"
)

type UserRepository struct {
	mock.Mock
}

func (m *UserRepository) GetByID(ctx context.Context, id string) (core.User, error) {
	args := m.Called(ctx, id)

	user, _ := args.Get(0).(core.User)
	return user, args.Error(1)
}

func (m *UserRepository) GetByEmail(ctx context.Context, email string) (core.User, error) {
	args := m.Called(ctx, email)

	user, _ := args.Get(0).(core.User)
	return user, args.Error(1)
}

func (m *UserRepository) GetByProvider(ctx context.Context, provider string, providerID string) (core.User, error) {
	args := m.Called(ctx, provider, providerID)

	user, _ := args.Get(0).(core.User)
	return user, args.Error(1)
}

func (m *UserRepository) Create(ctx context.Context, input core.CreateUserInput) (core.User, error) {
	args := m.Called(ctx, input)

	user, _ := args.Get(0).(core.User)
	return user, args.Error(1)
}

func (m *UserRepository) Update(ctx context.Context, user core.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}
