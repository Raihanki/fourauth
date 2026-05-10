package integrations

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Raihanki/fourauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func jsonBody(t *testing.T, v any) *bytes.Reader {
	t.Helper()

	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewReader(b)
}

func cookieByName(t *testing.T, res *http.Response, name string) *http.Cookie {
	t.Helper()

	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cookie %q not found", name)
	return nil
}

func TestAuth_LocalRegisterHandler_Integration(t *testing.T) {
	t.Run("invalid json", func(t *testing.T) {
		auth := newLocalAuth(t)

		req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		auth.LocalRegisterHandler().ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("success writes auth cookies", func(t *testing.T) {
		auth := newLocalAuth(t)

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
		refresh := cookieByName(t, res, "refresh_token")

		assert.NotEmpty(t, access.Value)
		assert.NotEmpty(t, refresh.Value)
	})

	t.Run("duplicate email", func(t *testing.T) {
		auth := newLocalAuth(t)

		firstReq := httptest.NewRequest(http.MethodPost, "/auth/register", jsonBody(t, map[string]any{
			"email":    "user@example.com",
			"password": "password123",
			"name":     "User",
			"role":     "user",
		}))
		firstReq.Header.Set("Content-Type", "application/json")
		firstRR := httptest.NewRecorder()
		auth.LocalRegisterHandler().ServeHTTP(firstRR, firstReq)
		require.Equal(t, http.StatusOK, firstRR.Code)

		secondReq := httptest.NewRequest(http.MethodPost, "/auth/register", jsonBody(t, map[string]any{
			"email":    "user@example.com",
			"password": "password123",
			"name":     "User",
			"role":     "user",
		}))
		secondReq.Header.Set("Content-Type", "application/json")
		secondRR := httptest.NewRecorder()

		auth.LocalRegisterHandler().ServeHTTP(secondRR, secondReq)

		assert.Equal(t, http.StatusBadRequest, secondRR.Code)
		assert.Contains(t, secondRR.Body.String(), core.ErrEmailCollision.Error())
	})
}

func TestAuth_LocalLoginHandler_Integration(t *testing.T) {
	t.Run("invalid json", func(t *testing.T) {
		auth := newLocalAuth(t)

		req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		auth.LocalLoginHandler().ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("wrong password", func(t *testing.T) {
		auth := newLocalAuth(t)

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
			"password": "wrong-password",
		}))
		loginReq.Header.Set("Content-Type", "application/json")
		loginRR := httptest.NewRecorder()

		auth.LocalLoginHandler().ServeHTTP(loginRR, loginReq)

		assert.Equal(t, http.StatusUnauthorized, loginRR.Code)
		assert.Contains(t, loginRR.Body.String(), core.ErrInvalidCreds.Error())
	})

	t.Run("success writes auth cookies", func(t *testing.T) {
		auth := newLocalAuth(t)

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
		refresh := cookieByName(t, res, "refresh_token")

		assert.NotEmpty(t, access.Value)
		assert.NotEmpty(t, refresh.Value)
	})
}

func TestAuth_MeHandler_Integration(t *testing.T) {
	auth := newLocalAuth(t)

	// register user
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

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(accessCookie)

	rr := httptest.NewRecorder()
	auth.RequireAuth(auth.MeHandler()).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "user@example.com")
}
