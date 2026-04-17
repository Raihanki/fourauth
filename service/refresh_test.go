package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/test/mocks"
)

func TestService_Refresh(t *testing.T) {
	ctx := context.Background()

	t.Run("invalid refresh token", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		refreshRepo := new(mocks.RefreshTokenRepository)
		issuer := new(mocks.Issuer)
		local := new(mocks.LocalProvider)
		google := new(mocks.GoogleProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:        repo,
			refreshRepo: refreshRepo,
			issuer:      issuer,
			local:       local,
			google:      google,
		}

		issuer.
			On("ParseRefreshToken", "bad-refresh-token").
			Return(core.RefreshClaims{}, errors.New("invalid token")).
			Once()

		got, err := svc.Refresh(ctx, "bad-refresh-token")

		require.Error(t, err)
		assert.ErrorIs(t, err, core.ErrInvalidToken)
		assert.Equal(t, core.TokenPair{}, got)

		issuer.AssertExpectations(t)
		repo.AssertNotCalled(t, "GetByID", mock.Anything, mock.Anything)
		issuer.AssertNotCalled(t, "IssueAccessToken", mock.Anything)
		issuer.AssertNotCalled(t, "IssueRefreshToken", mock.Anything)
	})

	t.Run("user not found", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		refreshRepo := new(mocks.RefreshTokenRepository)
		issuer := new(mocks.Issuer)
		local := new(mocks.LocalProvider)
		google := new(mocks.GoogleProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:        repo,
			refreshRepo: refreshRepo,
			issuer:      issuer,
			local:       local,
			google:      google,
		}

		issuer.
			On("ParseRefreshToken", "valid-refresh-token").
			Return(core.RefreshClaims{
				Subject: "user-1",
				TokenID: "token-123",
			}, nil).
			Once()

		repo.
			On("GetByID", mock.Anything, "user-1").
			Return(nil, errors.New("not found")).
			Once()

		got, err := svc.Refresh(ctx, "valid-refresh-token")

		require.Error(t, err)
		assert.ErrorIs(t, err, core.ErrUnauthorized)
		assert.Equal(t, core.TokenPair{}, got)

		issuer.AssertExpectations(t)
		repo.AssertExpectations(t)
		issuer.AssertNotCalled(t, "IssueAccessToken", mock.Anything)
		issuer.AssertNotCalled(t, "IssueRefreshToken", mock.Anything)
	})

	t.Run("issue access token fails", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		refreshRepo := new(mocks.RefreshTokenRepository)
		issuer := new(mocks.Issuer)
		local := new(mocks.LocalProvider)
		google := new(mocks.GoogleProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:        repo,
			refreshRepo: refreshRepo,
			issuer:      issuer,
			local:       local,
			google:      google,
		}

		user := testUser{
			id:    "user-1",
			email: "user@example.com",
			role:  "user",
		}

		issuer.
			On("ParseRefreshToken", "valid-refresh-token").
			Return(core.RefreshClaims{
				Subject: "user-1",
				TokenID: "token-123",
			}, nil).
			Once()

		repo.
			On("GetByID", mock.Anything, "user-1").
			Return(user, nil).
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

		got, err := svc.Refresh(ctx, "valid-refresh-token")

		require.Error(t, err)
		assert.EqualError(t, err, "issue access failed")
		assert.Equal(t, core.TokenPair{}, got)

		issuer.AssertExpectations(t)
		repo.AssertExpectations(t)
		issuer.AssertNotCalled(t, "IssueRefreshToken", mock.Anything)
	})

	t.Run("issue refresh token fails", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		refreshRepo := new(mocks.RefreshTokenRepository)
		issuer := new(mocks.Issuer)
		local := new(mocks.LocalProvider)
		google := new(mocks.GoogleProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:        repo,
			refreshRepo: refreshRepo,
			issuer:      issuer,
			local:       local,
			google:      google,
		}

		user := testUser{
			id:    "user-1",
			email: "user@example.com",
			role:  "user",
		}

		issuer.
			On("ParseRefreshToken", "valid-refresh-token").
			Return(core.RefreshClaims{
				Subject: "user-1",
				TokenID: "token-123",
			}, nil).
			Once()

		repo.
			On("GetByID", mock.Anything, "user-1").
			Return(user, nil).
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
			Return(core.Token{}, errors.New("issue refresh failed")).
			Once()

		got, err := svc.Refresh(ctx, "valid-refresh-token")

		require.Error(t, err)
		assert.EqualError(t, err, "issue refresh failed")
		assert.Equal(t, core.TokenPair{}, got)

		issuer.AssertExpectations(t)
		repo.AssertExpectations(t)
	})

	t.Run("success", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		refreshRepo := new(mocks.RefreshTokenRepository)
		issuer := new(mocks.Issuer)
		local := new(mocks.LocalProvider)
		google := new(mocks.GoogleProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:        repo,
			refreshRepo: refreshRepo,
			issuer:      issuer,
			local:       local,
			google:      google,
		}

		user := testUser{
			id:    "user-1",
			email: "user@example.com",
			role:  "user",
		}

		issuer.
			On("ParseRefreshToken", "valid-refresh-token").
			Return(core.RefreshClaims{
				Subject: "user-1",
				TokenID: "token-123",
			}, nil).
			Once()

		repo.
			On("GetByID", mock.Anything, "user-1").
			Return(user, nil).
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

		got, err := svc.Refresh(ctx, "valid-refresh-token")

		require.NoError(t, err)
		assert.Equal(t, "access-token", got.AccessToken.Value)
		assert.Equal(t, "refresh-token", got.RefreshToken.Value)

		issuer.AssertExpectations(t)
		repo.AssertExpectations(t)
	})
}
