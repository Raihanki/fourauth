package integrations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Raihanki/fourauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	GOOGLE_CLIENT_ID     = "your_google_client_id"
	GOOGLE_CLIENT_SECRET = "your_google_client_secret"
	GOOGLE_REDIRECT_URL  = "http://localhost:8000/google-callback"
	GOOGLE_TEST_EMAIL    = "your_email_adress"
	GOOGLE_CALLBACK_CODE = "your_google_callback_code"
)

func TestAuth_GoogleRedirectHandler_Live(t *testing.T) {
	auth := newAuthGoogle(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/google", nil)
	rr := httptest.NewRecorder()

	auth.GoogleRedirectHandler().ServeHTTP(rr, req)

	res := rr.Result()
	defer res.Body.Close()

	require.GreaterOrEqual(t, res.StatusCode, 300)
	require.Less(t, res.StatusCode, 400)

	loc := res.Header.Get("Location")
	require.NotEmpty(t, loc)
	t.Logf("open this URL in a browser: %s", loc)

	u, err := url.Parse(loc)
	require.NoError(t, err)

	q := u.Query()
	assert.Equal(t, GOOGLE_CLIENT_ID, q.Get("client_id"))
	assert.Equal(t, GOOGLE_REDIRECT_URL, q.Get("redirect_uri"))
	assert.NotEmpty(t, q.Get("state"))
	assert.Contains(t, q.Get("scope"), "openid")
	assert.Contains(t, q.Get("scope"), "email")
	assert.Contains(t, q.Get("scope"), "profile")

	var stateCookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "oauth_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie)
	assert.NotEmpty(t, stateCookie.Value)
	assert.Equal(t, stateCookie.Value, q.Get("state"))
}

func TestAuth_GoogleCallback_Live(t *testing.T) {
	code := GOOGLE_CALLBACK_CODE
	auth := newAuthGoogle(t)

	result, err := auth.Service().LoginGoogleCallback(context.Background(), code)
	require.NoError(t, err)

	require.NotNil(t, result.User)
	assert.Equal(t, string(core.ProviderGoogle), result.User.GetProvider())
	assert.NotEmpty(t, result.User.GetEmail())

	providerID := result.User.GetProviderID()
	require.NotNil(t, providerID)
	assert.NotEmpty(t, *providerID)

	assert.NotEmpty(t, result.Tokens.AccessToken.Value)
	assert.NotEmpty(t, result.Tokens.RefreshToken.Value)

	if wantEmail := GOOGLE_TEST_EMAIL; wantEmail != "" {
		assert.Equal(t, wantEmail, result.User.GetEmail())
	}
}
