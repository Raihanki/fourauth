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

func TestService_GoogleAuthURL(t *testing.T) {
	google := new(mocks.GoogleProvider)

	svc := &Service{
		google: google,
	}

	google.
		On("AuthCodeURL", "state-123").
		Return("https://accounts.google.com/o/oauth2/v2/auth?state=state-123").
		Once()

	url, state, err := svc.GoogleAuthURL("state-123")

	require.NoError(t, err)
	assert.Equal(t, "https://accounts.google.com/o/oauth2/v2/auth?state=state-123", url)
	assert.Equal(t, "state-123", state)

	google.AssertExpectations(t)
}

func TestService_LoginGoogleCallback(t *testing.T) {
	ctx := context.Background()

	t.Run("exchange fails", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		issuer := new(mocks.Issuer)
		google := new(mocks.GoogleProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:   repo,
			issuer: issuer,
			google: google,
		}

		google.
			On("Exchange", mock.Anything, "bad-code").
			Return(nil, errors.New("exchange failed")).
			Once()

		got, err := svc.LoginGoogleCallback(ctx, "bad-code")

		require.Error(t, err)
		assert.EqualError(t, err, "exchange failed")
		assert.Equal(t, core.AuthResult{}, got)

		google.AssertExpectations(t)
		repo.AssertNotCalled(t, "GetByProvider", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("existing provider user", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		issuer := new(mocks.Issuer)
		google := new(mocks.GoogleProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:   repo,
			issuer: issuer,
			google: google,
		}

		identity := core.ExternalIdentity{
			Provider:      string(core.ProviderGoogle),
			ProviderID:    "google-123",
			Email:         "user@example.com",
			Name:          "Gaou",
			AvatarURL:     "https://example.com/avatar.png",
			EmailVerified: true,
		}

		user := testUser{
			id:            "user-1",
			email:         "user@example.com",
			provider:      string(core.ProviderGoogle),
			role:          "user",
			emailVerified: true,
		}

		google.
			On("Exchange", mock.Anything, "good-code").
			Return(identity, nil).
			Once()

		repo.
			On("GetByProvider", mock.Anything, identity.Provider, identity.ProviderID).
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

		got, err := svc.LoginGoogleCallback(ctx, "good-code")

		require.NoError(t, err)
		require.NotNil(t, got.User)
		assert.Equal(t, "user-1", got.User.GetID())
		assert.Equal(t, "user@example.com", got.User.GetEmail())
		assert.Equal(t, "access-token", got.Tokens.AccessToken.Value)
		assert.Equal(t, "refresh-token", got.Tokens.RefreshToken.Value)

		google.AssertExpectations(t)
		repo.AssertExpectations(t)
		issuer.AssertExpectations(t)
		repo.AssertNotCalled(t, "GetByEmail", mock.Anything, mock.Anything)
		repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
	})

	t.Run("existing provider user but issue token fails", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		issuer := new(mocks.Issuer)
		google := new(mocks.GoogleProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:   repo,
			issuer: issuer,
			google: google,
		}

		identity := core.ExternalIdentity{
			Provider:      string(core.ProviderGoogle),
			ProviderID:    "google-123",
			Email:         "user@example.com",
			Name:          "Gaou",
			AvatarURL:     "https://example.com/avatar.png",
			EmailVerified: true,
		}

		user := testUser{
			id:    "user-1",
			email: "user@example.com",
			role:  "user",
		}

		google.
			On("Exchange", mock.Anything, "good-code").
			Return(identity, nil).
			Once()

		repo.
			On("GetByProvider", mock.Anything, identity.Provider, identity.ProviderID).
			Return(user, nil).
			Once()

		issuer.
			On("IssueAccessToken", mock.Anything).
			Return(core.Token{}, errors.New("issue access failed")).
			Once()

		got, err := svc.LoginGoogleCallback(ctx, "good-code")

		require.Error(t, err)
		assert.EqualError(t, err, "issue access failed")
		assert.Equal(t, core.AuthResult{}, got)

		google.AssertExpectations(t)
		repo.AssertExpectations(t)
		issuer.AssertExpectations(t)
	})

	t.Run("email collision when provider user not found but email exists", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		issuer := new(mocks.Issuer)
		google := new(mocks.GoogleProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:   repo,
			issuer: issuer,
			google: google,
		}

		identity := core.ExternalIdentity{
			Provider:      string(core.ProviderGoogle),
			ProviderID:    "google-123",
			Email:         "user@example.com",
			Name:          "Gaou",
			AvatarURL:     "https://example.com/avatar.png",
			EmailVerified: true,
		}

		var noUser core.User
		existingUser := testUser{
			id:    "user-2",
			email: "user@example.com",
			role:  "user",
		}

		google.
			On("Exchange", mock.Anything, "good-code").
			Return(identity, nil).
			Once()

		repo.
			On("GetByProvider", mock.Anything, identity.Provider, identity.ProviderID).
			Return(noUser, errors.New("not found")).
			Once()

		repo.
			On("GetByEmail", mock.Anything, identity.Email).
			Return(existingUser, nil).
			Once()

		got, err := svc.LoginGoogleCallback(ctx, "good-code")

		require.Error(t, err)
		assert.ErrorIs(t, err, core.ErrEmailCollision)
		assert.Equal(t, core.AuthResult{}, got)

		google.AssertExpectations(t)
		repo.AssertExpectations(t)
		issuer.AssertNotCalled(t, "IssueAccessToken", mock.Anything)
		issuer.AssertNotCalled(t, "IssueRefreshToken", mock.Anything)
		repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
	})

	t.Run("create new google user", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		issuer := new(mocks.Issuer)
		google := new(mocks.GoogleProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:   repo,
			issuer: issuer,
			google: google,
		}

		identity := core.ExternalIdentity{
			Provider:      string(core.ProviderGoogle),
			ProviderID:    "google-123",
			Email:         "user@example.com",
			Name:          "Gaou",
			AvatarURL:     "https://example.com/avatar.png",
			EmailVerified: true,
		}

		createdUser := testUser{
			id:            "user-1",
			email:         "user@example.com",
			provider:      string(core.ProviderGoogle),
			role:          "user",
			emailVerified: true,
		}

		var noUser core.User

		google.
			On("Exchange", mock.Anything, "good-code").
			Return(identity, nil).
			Once()

		repo.
			On("GetByProvider", mock.Anything, identity.Provider, identity.ProviderID).
			Return(noUser, errors.New("not found")).
			Once()

		repo.
			On("GetByEmail", mock.Anything, identity.Email).
			Return(noUser, errors.New("not found")).
			Once()

		repo.
			On("Create", mock.Anything, mock.MatchedBy(func(in core.CreateUserInput) bool {
				return in.Email == "user@example.com" &&
					in.PasswordHash == nil &&
					in.Provider == string(core.ProviderGoogle) &&
					in.ProviderID != nil &&
					*in.ProviderID == "google-123" &&
					in.Name == "Gaou" &&
					in.AvatarURL != nil &&
					*in.AvatarURL == "https://example.com/avatar.png" &&
					in.Role == "user" &&
					in.EmailVerified
			})).
			Return(createdUser, nil).
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

		got, err := svc.LoginGoogleCallback(ctx, "good-code")

		require.NoError(t, err)
		require.NotNil(t, got.User)
		assert.Equal(t, "user-1", got.User.GetID())
		assert.Equal(t, "user@example.com", got.User.GetEmail())
		assert.Equal(t, "access-token", got.Tokens.AccessToken.Value)
		assert.Equal(t, "refresh-token", got.Tokens.RefreshToken.Value)

		google.AssertExpectations(t)
		repo.AssertExpectations(t)
		issuer.AssertExpectations(t)
	})

	t.Run("create new google user fails", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		issuer := new(mocks.Issuer)
		google := new(mocks.GoogleProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:   repo,
			issuer: issuer,
			google: google,
		}

		identity := core.ExternalIdentity{
			Provider:      string(core.ProviderGoogle),
			ProviderID:    "google-123",
			Email:         "user@example.com",
			Name:          "Gaou",
			AvatarURL:     "https://example.com/avatar.png",
			EmailVerified: true,
		}

		var noUser core.User

		google.
			On("Exchange", mock.Anything, "good-code").
			Return(identity, nil).
			Once()

		repo.
			On("GetByProvider", mock.Anything, identity.Provider, identity.ProviderID).
			Return(noUser, errors.New("not found")).
			Once()

		repo.
			On("GetByEmail", mock.Anything, identity.Email).
			Return(noUser, errors.New("not found")).
			Once()

		repo.
			On("Create", mock.Anything, mock.Anything).
			Return(noUser, errors.New("create failed")).
			Once()

		got, err := svc.LoginGoogleCallback(ctx, "good-code")

		require.Error(t, err)
		assert.EqualError(t, err, "create failed")
		assert.Equal(t, core.AuthResult{}, got)

		google.AssertExpectations(t)
		repo.AssertExpectations(t)
		issuer.AssertNotCalled(t, "IssueAccessToken", mock.Anything)
		issuer.AssertNotCalled(t, "IssueRefreshToken", mock.Anything)
	})

	t.Run("new google user issue token fails", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		issuer := new(mocks.Issuer)
		google := new(mocks.GoogleProvider)

		svc := &Service{
			tokenCfg: &core.TokenConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			repo:   repo,
			issuer: issuer,
			google: google,
		}

		identity := core.ExternalIdentity{
			Provider:      string(core.ProviderGoogle),
			ProviderID:    "google-123",
			Email:         "user@example.com",
			Name:          "Gaou",
			AvatarURL:     "https://example.com/avatar.png",
			EmailVerified: true,
		}

		createdUser := testUser{
			id:            "user-1",
			email:         "user@example.com",
			provider:      string(core.ProviderGoogle),
			role:          "user",
			emailVerified: true,
		}

		var noUser core.User

		google.
			On("Exchange", mock.Anything, "good-code").
			Return(identity, nil).
			Once()

		repo.
			On("GetByProvider", mock.Anything, identity.Provider, identity.ProviderID).
			Return(noUser, errors.New("not found")).
			Once()

		repo.
			On("GetByEmail", mock.Anything, identity.Email).
			Return(noUser, errors.New("not found")).
			Once()

		repo.
			On("Create", mock.Anything, mock.Anything).
			Return(createdUser, nil).
			Once()

		issuer.
			On("IssueAccessToken", mock.Anything).
			Return(core.Token{}, errors.New("issue access failed")).
			Once()

		got, err := svc.LoginGoogleCallback(ctx, "good-code")

		require.Error(t, err)
		assert.EqualError(t, err, "issue access failed")
		assert.Equal(t, core.AuthResult{}, got)

		google.AssertExpectations(t)
		repo.AssertExpectations(t)
		issuer.AssertExpectations(t)
	})
}
