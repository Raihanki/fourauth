package integrations

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuth_RefreshTokenHandler_Integration(t *testing.T) {
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

	res := registerRR.Result()
	defer res.Body.Close()

	refreshCookie := cookieByName(t, res, "refresh_token")
	require.NotEmpty(t, refreshCookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(refreshCookie)

	rr := httptest.NewRecorder()
	auth.RefreshTokenHandler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	refreshRes := rr.Result()
	defer refreshRes.Body.Close()

	newAccess := cookieByName(t, refreshRes, "access_token")
	newRefresh := cookieByName(t, refreshRes, "refresh_token")

	assert.NotEmpty(t, newAccess.Value)
	assert.NotEmpty(t, newRefresh.Value)
}
