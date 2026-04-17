package mocks

import (
	"net/http"

	"github.com/Raihanki/fourauth/core"
	"github.com/stretchr/testify/mock"
)

type Transport struct {
	mock.Mock
}

func (m *Transport) WriteTokens(w http.ResponseWriter, pair core.TokenPair) error {
	args := m.Called(w, pair)
	return args.Error(0)
}

func (m *Transport) ReadAccessToken(r *http.Request) (string, error) {
	args := m.Called(r)

	token, _ := args.Get(0).(string)
	return token, args.Error(1)
}

func (m *Transport) ReadRefreshToken(r *http.Request) (string, error) {
	args := m.Called(r)

	token, _ := args.Get(0).(string)
	return token, args.Error(1)
}

func (m *Transport) Clear(w http.ResponseWriter) error {
	args := m.Called(w)
	return args.Error(0)
}

func (m *Transport) Kind() core.TransportKind {
	args := m.Called()

	kind, _ := args.Get(0).(core.TransportKind)
	return kind
}
