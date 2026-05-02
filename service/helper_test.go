package service

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/test/mocks"
)

func TestService_issueTokenPair(t *testing.T) {
	t.Run("issue access token fails", func(t *testing.T) {
		issuer := new(mocks.Issuer)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			issuer:          issuer,
			useRefreshToken: true,
		}

		user := testUser{
			id:    "user-1",
			email: "user@example.com",
			role:  "user",
		}

		issuer.
			On("IssueAccessToken", mock.MatchedBy(func(c core.AccessClaims) bool {
				return c.Subject == "user-1" &&
					c.Email == "user@example.com" &&
					c.Role == "user" &&
					!c.ExpiresAt.IsZero()
			})).
			Return(core.Token{}, errors.New("issue access failed")).
			Once()

		got, err := svc.IssueTokenPair(user)

		require.Error(t, err)
		assert.EqualError(t, err, "issue access failed")
		assert.Equal(t, core.TokenPair{}, got)

		issuer.AssertExpectations(t)
		issuer.AssertNotCalled(t, "IssueRefreshToken", mock.Anything)
	})

	t.Run("issue refresh token fails", func(t *testing.T) {
		issuer := new(mocks.Issuer)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			issuer:          issuer,
			useRefreshToken: true,
		}

		user := testUser{
			id:    "user-1",
			email: "user@example.com",
			role:  "user",
		}

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

		got, err := svc.IssueTokenPair(user)

		require.Error(t, err)
		assert.EqualError(t, err, "issue refresh failed")
		assert.Equal(t, core.TokenPair{}, got)

		issuer.AssertExpectations(t)
	})

	t.Run("success", func(t *testing.T) {
		issuer := new(mocks.Issuer)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			issuer:          issuer,
			useRefreshToken: true,
		}

		user := testUser{
			id:    "user-1",
			email: "user@example.com",
			role:  "user",
		}

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

		got, err := svc.IssueTokenPair(user)

		require.NoError(t, err)
		assert.Equal(t, "access-token", got.AccessToken.Value)
		assert.Equal(t, "refresh-token", got.RefreshToken.Value)

		issuer.AssertExpectations(t)
	})

	t.Run("success without refresh token", func(t *testing.T) {
		issuer := new(mocks.Issuer)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			issuer:          issuer,
			useRefreshToken: false,
		}

		user := testUser{
			id:    "user-1",
			email: "user@example.com",
			role:  "user",
		}

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

		got, err := svc.IssueTokenPair(user)

		require.NoError(t, err)
		assert.Equal(t, "access-token", got.AccessToken.Value)
		assert.Empty(t, got.RefreshToken.Value)

		issuer.AssertExpectations(t)
		issuer.AssertNotCalled(t, "IssueRefreshToken", mock.Anything)
	})
}

func TestRandomTokenID(t *testing.T) {
	id1, err := randomTokenID()
	require.NoError(t, err)
	assert.NotEmpty(t, id1)

	id2, err := randomTokenID()
	require.NoError(t, err)
	assert.NotEmpty(t, id2)

	assert.NotEqual(t, id1, id2)

	// 32 random bytes, raw base64url encoded = 43 chars
	assert.Len(t, id1, 43)
	assert.Len(t, id2, 43)
}
