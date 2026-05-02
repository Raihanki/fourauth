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

func TestService_LoginLocal(t *testing.T) {
	ctx := context.Background()

	t.Run("email not found", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		refreshRepo := new(mocks.RefreshTokenRepository)
		issuer := new(mocks.Issuer)
		local := new(mocks.LocalProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:            repo,
			refreshRepo:     refreshRepo,
			issuer:          issuer,
			local:           local,
			useRefreshToken: true,
		}

		repo.
			On("GetByEmail", mock.Anything, "user@example.com").
			Return(nil, errors.New("not found")).
			Once()

		got, err := svc.LoginLocal(ctx, "user@example.com", "password123")

		require.Error(t, err)
		assert.ErrorIs(t, err, core.ErrInvalidCreds)
		assert.Equal(t, core.AuthResult{}, got)

		repo.AssertExpectations(t)
		local.AssertNotCalled(t, "Compare", mock.Anything, mock.Anything)
		issuer.AssertNotCalled(t, "IssueAccessToken", mock.Anything)
		issuer.AssertNotCalled(t, "IssueRefreshToken", mock.Anything)
	})

	t.Run("password hash is nil", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		refreshRepo := new(mocks.RefreshTokenRepository)
		issuer := new(mocks.Issuer)
		local := new(mocks.LocalProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:            repo,
			refreshRepo:     refreshRepo,
			issuer:          issuer,
			local:           local,
			useRefreshToken: true,
		}

		user := testUser{
			id:    "user-1",
			email: "user@example.com",
			role:  "user",
		}

		repo.
			On("GetByEmail", mock.Anything, "user@example.com").
			Return(user, nil).
			Once()

		got, err := svc.LoginLocal(ctx, "user@example.com", "password123")

		require.Error(t, err)
		assert.ErrorIs(t, err, core.ErrInvalidCreds)
		assert.Equal(t, core.AuthResult{}, got)

		repo.AssertExpectations(t)
		local.AssertNotCalled(t, "Compare", mock.Anything, mock.Anything)
		issuer.AssertNotCalled(t, "IssueAccessToken", mock.Anything)
		issuer.AssertNotCalled(t, "IssueRefreshToken", mock.Anything)
	})

	t.Run("password hash is empty", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		refreshRepo := new(mocks.RefreshTokenRepository)
		issuer := new(mocks.Issuer)
		local := new(mocks.LocalProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:            repo,
			refreshRepo:     refreshRepo,
			issuer:          issuer,
			local:           local,
			useRefreshToken: true,
		}

		emptyHash := ""
		user := testUser{
			id:           "user-1",
			email:        "user@example.com",
			passwordHash: &emptyHash,
			role:         "user",
		}

		repo.
			On("GetByEmail", mock.Anything, "user@example.com").
			Return(user, nil).
			Once()

		got, err := svc.LoginLocal(ctx, "user@example.com", "password123")

		require.Error(t, err)
		assert.ErrorIs(t, err, core.ErrInvalidCreds)
		assert.Equal(t, core.AuthResult{}, got)

		repo.AssertExpectations(t)
		local.AssertNotCalled(t, "Compare", mock.Anything, mock.Anything)
		issuer.AssertNotCalled(t, "IssueAccessToken", mock.Anything)
		issuer.AssertNotCalled(t, "IssueRefreshToken", mock.Anything)
	})

	t.Run("password compare fails", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		refreshRepo := new(mocks.RefreshTokenRepository)
		issuer := new(mocks.Issuer)
		local := new(mocks.LocalProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:            repo,
			refreshRepo:     refreshRepo,
			issuer:          issuer,
			local:           local,
			useRefreshToken: true,
		}

		hash := "hashed-password"
		user := testUser{
			id:           "user-1",
			email:        "user@example.com",
			passwordHash: &hash,
			role:         "user",
		}

		repo.
			On("GetByEmail", mock.Anything, "user@example.com").
			Return(user, nil).
			Once()

		local.
			On("Compare", "hashed-password", "password123").
			Return(errors.New("invalid password")).
			Once()

		got, err := svc.LoginLocal(ctx, "user@example.com", "password123")

		require.Error(t, err)
		assert.ErrorIs(t, err, core.ErrInvalidCreds)
		assert.Equal(t, core.AuthResult{}, got)

		repo.AssertExpectations(t)
		local.AssertExpectations(t)
		issuer.AssertNotCalled(t, "IssueAccessToken", mock.Anything)
		issuer.AssertNotCalled(t, "IssueRefreshToken", mock.Anything)
	})

	t.Run("issue access token fails", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		refreshRepo := new(mocks.RefreshTokenRepository)
		issuer := new(mocks.Issuer)
		local := new(mocks.LocalProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:            repo,
			refreshRepo:     refreshRepo,
			issuer:          issuer,
			local:           local,
			useRefreshToken: true,
		}

		hash := "hashed-password"
		user := testUser{
			id:           "user-1",
			email:        "user@example.com",
			passwordHash: &hash,
			role:         "user",
		}

		repo.
			On("GetByEmail", mock.Anything, "user@example.com").
			Return(user, nil).
			Once()

		local.
			On("Compare", "hashed-password", "password123").
			Return(nil).
			Once()

		issuer.
			On("IssueAccessToken", mock.MatchedBy(func(c core.AccessClaims) bool {
				return c.Subject == "user-1" &&
					c.Email == "user@example.com" &&
					c.Role == "user" &&
					!c.ExpiresAt.IsZero()
			})).
			Return(core.Token{}, errors.New("issue access failed")).
			Once()

		got, err := svc.LoginLocal(ctx, "user@example.com", "password123")

		require.Error(t, err)
		assert.EqualError(t, err, "issue access failed")
		assert.Equal(t, core.AuthResult{}, got)

		repo.AssertExpectations(t)
		local.AssertExpectations(t)
		issuer.AssertExpectations(t)
		issuer.AssertNotCalled(t, "IssueRefreshToken", mock.Anything)
	})

	t.Run("issue refresh token fails", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		refreshRepo := new(mocks.RefreshTokenRepository)
		issuer := new(mocks.Issuer)
		local := new(mocks.LocalProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:            repo,
			refreshRepo:     refreshRepo,
			issuer:          issuer,
			local:           local,
			useRefreshToken: true,
		}

		hash := "hashed-password"
		user := testUser{
			id:           "user-1",
			email:        "user@example.com",
			passwordHash: &hash,
			role:         "user",
		}

		repo.
			On("GetByEmail", mock.Anything, "user@example.com").
			Return(user, nil).
			Once()

		local.
			On("Compare", "hashed-password", "password123").
			Return(nil).
			Once()

		issuer.
			On("IssueAccessToken", mock.MatchedBy(func(c core.AccessClaims) bool {
				return c.Subject == "user-1" &&
					c.Email == "user@example.com" &&
					c.Role == "user" &&
					!c.ExpiresAt.IsZero()
			})).
			Return(core.Token{Value: "access-token"}, nil).
			Once()

		issuer.
			On("IssueRefreshToken", mock.MatchedBy(func(c core.RefreshClaims) bool {
				return c.Subject == "user-1" &&
					c.TokenID != "" &&
					!c.ExpiresAt.IsZero()
			})).
			Return(core.Token{}, errors.New("issue refresh failed")).
			Once()

		got, err := svc.LoginLocal(ctx, "user@example.com", "password123")

		require.Error(t, err)
		assert.EqualError(t, err, "issue refresh failed")
		assert.Equal(t, core.AuthResult{}, got)

		repo.AssertExpectations(t)
		local.AssertExpectations(t)
		issuer.AssertExpectations(t)
	})

	t.Run("success", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		refreshRepo := new(mocks.RefreshTokenRepository)
		issuer := new(mocks.Issuer)
		local := new(mocks.LocalProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:            repo,
			refreshRepo:     refreshRepo,
			issuer:          issuer,
			local:           local,
			useRefreshToken: true,
		}

		hash := "hashed-password"
		user := testUser{
			id:           "user-1",
			email:        "user@example.com",
			passwordHash: &hash,
			role:         "user",
		}

		repo.
			On("GetByEmail", mock.Anything, "user@example.com").
			Return(user, nil).
			Once()

		local.
			On("Compare", "hashed-password", "password123").
			Return(nil).
			Once()

		issuer.
			On("IssueAccessToken", mock.MatchedBy(func(c core.AccessClaims) bool {
				return c.Subject == "user-1" &&
					c.Email == "user@example.com" &&
					c.Role == "user" &&
					!c.ExpiresAt.IsZero()
			})).
			Return(core.Token{
				Value:     "access-token",
				ExpiredAt: time.Now().Add(15 * time.Minute),
			}, nil).
			Once()

		issuer.
			On("IssueRefreshToken", mock.MatchedBy(func(c core.RefreshClaims) bool {
				return c.Subject == "user-1" &&
					c.TokenID != "" &&
					!c.ExpiresAt.IsZero()
			})).
			Return(core.Token{
				Value:     "refresh-token",
				ExpiredAt: time.Now().Add(24 * time.Hour),
			}, nil).
			Once()

		got, err := svc.LoginLocal(ctx, "user@example.com", "password123")

		require.NoError(t, err)
		require.NotNil(t, got.User)
		assert.Equal(t, "user-1", got.User.GetID())
		assert.Equal(t, "user@example.com", got.User.GetEmail())
		assert.Equal(t, "access-token", got.Tokens.AccessToken.Value)
		assert.Equal(t, "refresh-token", got.Tokens.RefreshToken.Value)

		repo.AssertExpectations(t)
		local.AssertExpectations(t)
		issuer.AssertExpectations(t)
	})
}
