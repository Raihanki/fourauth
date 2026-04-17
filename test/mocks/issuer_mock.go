package mocks

import (
	"github.com/Raihanki/fourauth/core"
	"github.com/stretchr/testify/mock"
)

type Issuer struct {
	mock.Mock
}

func (m *Issuer) IssueAccessToken(claims core.AccessClaims) (core.Token, error) {
	args := m.Called(claims)

	token, _ := args.Get(0).(core.Token)
	return token, args.Error(1)
}

func (m *Issuer) IssueRefreshToken(claims core.RefreshClaims) (core.Token, error) {
	args := m.Called(claims)

	token, _ := args.Get(0).(core.Token)
	return token, args.Error(1)
}

func (m *Issuer) ParseAccessToken(raw string) (core.AccessClaims, error) {
	args := m.Called(raw)

	claims, _ := args.Get(0).(core.AccessClaims)
	return claims, args.Error(1)
}

func (m *Issuer) ParseRefreshToken(raw string) (core.RefreshClaims, error) {
	args := m.Called(raw)

	claims, _ := args.Get(0).(core.RefreshClaims)
	return claims, args.Error(1)
}

func (m *Issuer) Kind() core.TokenKind {
	args := m.Called()

	kind, _ := args.Get(0).(core.TokenKind)
	return kind
}
