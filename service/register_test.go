package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/test/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type testUser struct {
	id            string
	email         string
	passwordHash  *string
	provider      string
	providerID    *string
	role          string
	emailVerified bool
}

func (u testUser) GetID() string            { return u.id }
func (u testUser) GetEmail() string         { return u.email }
func (u testUser) GetPasswordHash() *string { return u.passwordHash }
func (u testUser) GetProvider() string      { return u.provider }
func (u testUser) GetProviderID() *string   { return u.providerID }
func (u testUser) GetRole() string          { return u.role }
func (u testUser) IsEmailVerified() bool    { return u.emailVerified }

func TestService_Register_Success(t *testing.T) {
	repo := new(mocks.UserRepository)
	refreshRepo := new(mocks.RefreshTokenRepository)
	issuer := new(mocks.Issuer)
	local := new(mocks.LocalProvider)

	svc := &Service{
		tokenCfg: &core.TokenConfig{
			AccessTokenTTL:  time.Minute,
			RefreshTokenTTL: time.Hour,
		},
		repo:        repo,
		refreshRepo: refreshRepo,
		issuer:      issuer,
		local:       local,
	}

	ctx := context.Background()

	// email not found
	repo.
		On("GetByEmail", mock.Anything, "user@example.com").
		Return(core.User(nil), errors.New("not found")).
		Once()

	// hash password
	local.
		On("Hash", "password123").
		Return("hashed-password", nil).
		Once()

	// fake user
	user := testUser{
		id:    "user-1",
		email: "user@example.com",
		role:  "user",
	}

	// create user
	repo.
		On("Create", mock.Anything, mock.MatchedBy(func(in core.CreateUserInput) bool {
			return in.Email == "user@example.com" &&
				in.PasswordHash != nil &&
				*in.PasswordHash == "hashed-password" &&
				in.Provider == string(core.ProviderLocal)
		})).
		Return(user, nil).
		Once()

	// issue tokens
	issuer.
		On("IssueAccessToken", mock.Anything).
		Return(core.Token{Value: "access"}, nil).
		Once()

	issuer.
		On("IssueRefreshToken", mock.Anything).
		Return(core.Token{Value: "refresh"}, nil).
		Once()

	// act
	res, err := svc.Register(ctx, RegisterInput{
		Email:    "user@example.com",
		Password: "password123",
		Name:     "Gaou",
		Role:     "user",
	})

	// assert
	require.NoError(t, err)
	require.NotNil(t, res.User)

	assert.Equal(t, "user@example.com", res.User.GetEmail())
	assert.Equal(t, "access", res.Tokens.AccessToken.Value)
	assert.Equal(t, "refresh", res.Tokens.RefreshToken.Value)

	repo.AssertExpectations(t)
	local.AssertExpectations(t)
	issuer.AssertExpectations(t)
}
