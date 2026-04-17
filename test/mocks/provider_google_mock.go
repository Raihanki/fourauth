package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"

	"github.com/Raihanki/fourauth/core"
)

type GoogleProvider struct {
	mock.Mock
}

func (m *GoogleProvider) AuthCodeURL(state string) string {
	args := m.Called(state)

	url, _ := args.Get(0).(string)
	return url
}

func (m *GoogleProvider) Exchange(ctx context.Context, code string) (core.ExternalIdentity, error) {
	args := m.Called(ctx, code)

	identity, _ := args.Get(0).(core.ExternalIdentity)
	return identity, args.Error(1)
}

func (m *GoogleProvider) UserFromGoogleToken(ctx context.Context, accessToken string) (core.ExternalIdentity, error) {
	args := m.Called(ctx, accessToken)

	identity, _ := args.Get(0).(core.ExternalIdentity)
	return identity, args.Error(1)
}
