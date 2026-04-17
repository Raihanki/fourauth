package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/test/mocks"
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

func TestAuthMiddleware_RequireAuth(t *testing.T) {
	t.Run("unauthorized when access token missing", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		issuer := new(mocks.Issuer)
		transport := new(mocks.Transport)

		transport.
			On("ReadAccessToken", mock.Anything).
			Return("", core.ErrUnauthorized).
			Once()

		m := AuthMiddleware{
			Repo:      repo,
			Issuer:    issuer,
			Transport: transport,
		}

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		rr := httptest.NewRecorder()

		m.RequireAuth(next).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.False(t, nextCalled)
		assert.Contains(t, rr.Body.String(), core.ErrUnauthorized.Error())

		transport.AssertExpectations(t)
		issuer.AssertNotCalled(t, "ParseAccessToken", mock.Anything)
		repo.AssertNotCalled(t, "GetByID", mock.Anything, mock.Anything)
	})

	t.Run("unauthorized when token invalid", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		issuer := new(mocks.Issuer)
		transport := new(mocks.Transport)

		transport.
			On("ReadAccessToken", mock.Anything).
			Return("bad-token", nil).
			Once()

		issuer.
			On("ParseAccessToken", "bad-token").
			Return(core.AccessClaims{}, core.ErrInvalidToken).
			Once()

		m := AuthMiddleware{
			Repo:      repo,
			Issuer:    issuer,
			Transport: transport,
		}

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		rr := httptest.NewRecorder()

		m.RequireAuth(next).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.False(t, nextCalled)
		assert.Contains(t, rr.Body.String(), core.ErrUnauthorized.Error())

		transport.AssertExpectations(t)
		issuer.AssertExpectations(t)
		repo.AssertNotCalled(t, "GetByID", mock.Anything, mock.Anything)
	})

	t.Run("unauthorized when user not found", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		issuer := new(mocks.Issuer)
		transport := new(mocks.Transport)

		transport.
			On("ReadAccessToken", mock.Anything).
			Return("valid-token", nil).
			Once()

		issuer.
			On("ParseAccessToken", "valid-token").
			Return(core.AccessClaims{Subject: "user-1"}, nil).
			Once()

		repo.
			On("GetByID", mock.Anything, "user-1").
			Return(testUser{}, core.ErrUnauthorized).
			Once()

		m := AuthMiddleware{
			Repo:      repo,
			Issuer:    issuer,
			Transport: transport,
		}

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		rr := httptest.NewRecorder()

		m.RequireAuth(next).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.False(t, nextCalled)
		assert.Contains(t, rr.Body.String(), core.ErrUnauthorized.Error())

		transport.AssertExpectations(t)
		issuer.AssertExpectations(t)
		repo.AssertExpectations(t)
	})

	t.Run("success calls next and injects user into context", func(t *testing.T) {
		repo := new(mocks.UserRepository)
		issuer := new(mocks.Issuer)
		transport := new(mocks.Transport)

		wantUser := testUser{
			id:            "user-1",
			email:         "user@example.com",
			role:          "user",
			emailVerified: true,
		}

		transport.
			On("ReadAccessToken", mock.Anything).
			Return("valid-token", nil).
			Once()

		issuer.
			On("ParseAccessToken", "valid-token").
			Return(core.AccessClaims{Subject: "user-1"}, nil).
			Once()

		repo.
			On("GetByID", mock.Anything, "user-1").
			Return(wantUser, nil).
			Once()

		m := AuthMiddleware{
			Repo:      repo,
			Issuer:    issuer,
			Transport: transport,
		}

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true

			gotUser, ok := UserFromContext(r.Context())
			require.True(t, ok)
			assert.Equal(t, wantUser, gotUser)

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})

		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		rr := httptest.NewRecorder()

		m.RequireAuth(next).ServeHTTP(rr, req)

		assert.True(t, nextCalled)
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "ok", rr.Body.String())

		transport.AssertExpectations(t)
		issuer.AssertExpectations(t)
		repo.AssertExpectations(t)
	})
}
