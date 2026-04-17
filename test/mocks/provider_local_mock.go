package mocks

import "github.com/stretchr/testify/mock"

type LocalProvider struct {
	mock.Mock
}

func (m *LocalProvider) Hash(password string) (string, error) {
	args := m.Called(password)

	hashed, _ := args.Get(0).(string)
	return hashed, args.Error(1)
}

func (m *LocalProvider) Compare(hash, password string) error {
	args := m.Called(hash, password)
	return args.Error(0)
}
