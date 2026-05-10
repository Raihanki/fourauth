package integrations

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Raihanki/fourauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuth_WithoutRefreshToken(t *testing.T) {
	t.Run("register does not set refresh cookie", func(t *testing.T) {
		auth := newLocalAuthWithoutRefresh(t)

		req := httptest.NewRequest(http.MethodPost, "/auth/register", jsonBody(t, map[string]any{
			"email":    "user@example.com",
			"password": "password123",
			"name":     "User",
			"role":     "user",
		}))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		auth.LocalRegisterHandler().ServeHTTP(rr, req)

		res := rr.Result()
		defer res.Body.Close()

		assert.Equal(t, http.StatusOK, res.StatusCode)

		access := cookieByName(t, res, "access_token")
		assert.NotEmpty(t, access.Value)

		for _, c := range res.Cookies() {
			assert.NotEqual(t, "refresh_token", c.Name, "refresh_token cookie should not be set")
		}
	})

	t.Run("login does not set refresh cookie", func(t *testing.T) {
		auth := newLocalAuthWithoutRefresh(t)

		registerReq := httptest.NewRequest(http.MethodPost, "/auth/register", jsonBody(t, map[string]any{
			"email":    "user@example.com",
			"password": "password123",
			"name":     "User",
			"role":     "user",
		}))
		registerReq.Header.Set("Content-Type", "application/json")
		registerRR := httptest.NewRecorder()
		auth.LocalRegisterHandler().ServeHTTP(registerRR, registerReq)
		require.Equal(t, http.StatusOK, registerRR.Code)

		loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", jsonBody(t, map[string]any{
			"email":    "user@example.com",
			"password": "password123",
		}))
		loginReq.Header.Set("Content-Type", "application/json")
		loginRR := httptest.NewRecorder()
		auth.LocalLoginHandler().ServeHTTP(loginRR, loginReq)

		res := loginRR.Result()
		defer res.Body.Close()

		assert.Equal(t, http.StatusOK, res.StatusCode)

		access := cookieByName(t, res, "access_token")
		assert.NotEmpty(t, access.Value)

		for _, c := range res.Cookies() {
			assert.NotEqual(t, "refresh_token", c.Name, "refresh_token cookie should not be set")
		}
	})

	t.Run("refresh token handler returns 404", func(t *testing.T) {
		auth := newLocalAuthWithoutRefresh(t)

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		rr := httptest.NewRecorder()

		auth.RefreshTokenHandler().ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("service refresh returns disabled error", func(t *testing.T) {
		auth := newLocalAuthWithoutRefresh(t)

		_, err := auth.Service().Refresh(t.Context(), "some-token")
		assert.ErrorIs(t, err, core.ErrRefreshTokenDisabled)
	})

	t.Run("me handler still works with access token", func(t *testing.T) {
		auth := newLocalAuthWithoutRefresh(t)

		registerReq := httptest.NewRequest(http.MethodPost, "/auth/register", jsonBody(t, map[string]any{
			"email":    "user@example.com",
			"password": "password123",
			"name":     "User",
			"role":     "user",
		}))
		registerReq.Header.Set("Content-Type", "application/json")
		registerRR := httptest.NewRecorder()
		auth.LocalRegisterHandler().ServeHTTP(registerRR, registerReq)
		require.Equal(t, http.StatusOK, registerRR.Code)

		res := registerRR.Result()
		defer res.Body.Close()

		accessCookie := cookieByName(t, res, "access_token")
		require.NotEmpty(t, accessCookie.Value)

		meReq := httptest.NewRequest(http.MethodGet, "/me", nil)
		meReq.AddCookie(accessCookie)
		meRR := httptest.NewRecorder()

		auth.RequireAuth(auth.MeHandler()).ServeHTTP(meRR, meReq)

		assert.Equal(t, http.StatusOK, meRR.Code)
		assert.Contains(t, meRR.Body.String(), "user@example.com")
	})
}
