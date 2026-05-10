package fourauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/provider/local"
	"github.com/Raihanki/fourauth/test/integrations/memory"
	"github.com/Raihanki/fourauth/token/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestIssuer(t *testing.T) *jwt.Issuer {
	t.Helper()
	pub, priv, err := jwt.GenerateKeyPair()
	require.NoError(t, err)
	return jwt.New(jwt.Config{
		PrivateKey: priv,
		PublicKey:  pub,
	})
}

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

func TestWithInsecureCookies_BeforeWithCookieTransport(t *testing.T) {
	auth, err := New(
		WithUserRepository(memory.NewMemUserRepo()),
		WithRefreshTokenRepository(memory.NewMemRefreshRepo()),
		WithIssuer(newTestIssuer(t)),
		WithInsecureCookies(),
		WithCookieTransport(),
		WithLocalAuth(),
		WithHasher(local.NewBcrypt()),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/register", jsonBody(t, map[string]any{
		"email":    "user@example.com",
		"password": "password123",
		"name":     "Test",
		"role":     "user",
	}))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	auth.LocalRegisterHandler().ServeHTTP(rr, req)
	res := rr.Result()
	defer res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode)

	access := cookieByName(t, res, "access_token")
	refresh := cookieByName(t, res, "refresh_token")

	assert.False(t, access.Secure, "access cookie should not be Secure")
	assert.True(t, access.HttpOnly, "access cookie should always be HttpOnly")
	assert.False(t, refresh.Secure, "refresh cookie should not be Secure")
	assert.True(t, refresh.HttpOnly, "refresh cookie should always be HttpOnly")
}

func TestWithInsecureCookies_AfterWithCookieTransport(t *testing.T) {
	auth, err := New(
		WithUserRepository(memory.NewMemUserRepo()),
		WithRefreshTokenRepository(memory.NewMemRefreshRepo()),
		WithIssuer(newTestIssuer(t)),
		WithCookieTransport(),
		WithInsecureCookies(),
		WithLocalAuth(),
		WithHasher(local.NewBcrypt()),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/register", jsonBody(t, map[string]any{
		"email":    "user2@example.com",
		"password": "password123",
		"name":     "Test",
		"role":     "user",
	}))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	auth.LocalRegisterHandler().ServeHTTP(rr, req)
	res := rr.Result()
	defer res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode)

	access := cookieByName(t, res, "access_token")
	refresh := cookieByName(t, res, "refresh_token")

	assert.False(t, access.Secure, "access cookie should not be Secure")
	assert.True(t, access.HttpOnly, "access cookie should always be HttpOnly")
	assert.False(t, refresh.Secure, "refresh cookie should not be Secure")
	assert.True(t, refresh.HttpOnly, "refresh cookie should always be HttpOnly")
}

func TestWithInsecureCookies_DefaultTransport(t *testing.T) {
	auth, err := New(
		WithUserRepository(memory.NewMemUserRepo()),
		WithRefreshTokenRepository(memory.NewMemRefreshRepo()),
		WithIssuer(newTestIssuer(t)),
		WithInsecureCookies(),
		WithLocalAuth(),
		WithHasher(local.NewBcrypt()),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/register", jsonBody(t, map[string]any{
		"email":    "user3@example.com",
		"password": "password123",
		"name":     "Test",
		"role":     "user",
	}))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	auth.LocalRegisterHandler().ServeHTTP(rr, req)
	res := rr.Result()
	defer res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode)

	access := cookieByName(t, res, "access_token")
	refresh := cookieByName(t, res, "refresh_token")

	assert.False(t, access.Secure, "access cookie should not be Secure")
	assert.True(t, access.HttpOnly, "access cookie should always be HttpOnly")
	assert.False(t, refresh.Secure, "refresh cookie should not be Secure")
	assert.True(t, refresh.HttpOnly, "refresh cookie should always be HttpOnly")
}

func TestWithoutInsecureCookies_DefaultsToSecure(t *testing.T) {
	auth, err := New(
		WithUserRepository(memory.NewMemUserRepo()),
		WithRefreshTokenRepository(memory.NewMemRefreshRepo()),
		WithIssuer(newTestIssuer(t)),
		WithCookieTransport(),
		WithLocalAuth(),
		WithHasher(local.NewBcrypt()),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/register", jsonBody(t, map[string]any{
		"email":    "user4@example.com",
		"password": "password123",
		"name":     "Test",
		"role":     "user",
	}))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	auth.LocalRegisterHandler().ServeHTTP(rr, req)
	res := rr.Result()
	defer res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode)

	access := cookieByName(t, res, "access_token")
	refresh := cookieByName(t, res, "refresh_token")

	assert.True(t, access.Secure, "access cookie should be Secure by default")
	assert.True(t, access.HttpOnly, "access cookie should be HttpOnly by default")
	assert.True(t, refresh.Secure, "refresh cookie should be Secure by default")
	assert.True(t, refresh.HttpOnly, "refresh cookie should be HttpOnly by default")
}

func TestWithInsecureCookies_CSRFCookieIsInsecure(t *testing.T) {
	auth, err := New(
		WithUserRepository(memory.NewMemUserRepo()),
		WithRefreshTokenRepository(memory.NewMemRefreshRepo()),
		WithIssuer(newTestIssuer(t)),
		WithInsecureCookies(),
		WithCookieTransport(),
		WithLocalAuth(),
		WithHasher(local.NewBcrypt()),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/csrf", nil)
	rr := httptest.NewRecorder()

	auth.CSRFHandler().ServeHTTP(rr, req)
	res := rr.Result()
	defer res.Body.Close()

	require.Equal(t, http.StatusNoContent, res.StatusCode)

	csrfCookie := cookieByName(t, res, "XSRF-TOKEN")
	assert.False(t, csrfCookie.Secure, "CSRF cookie should not be Secure")
	assert.False(t, csrfCookie.HttpOnly, "CSRF cookie should not be HttpOnly")
}

func TestWithInsecureCookies_GoogleStateCookieIsInsecure(t *testing.T) {
	auth, err := New(
		WithUserRepository(memory.NewMemUserRepo()),
		WithRefreshTokenRepository(memory.NewMemRefreshRepo()),
		WithIssuer(newTestIssuer(t)),
		WithInsecureCookies(),
		WithCookieTransport(),
		WithGoogleAuth(core.GoogleConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost:8000/callback",
		}),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/google", nil)
	rr := httptest.NewRecorder()

	auth.GoogleRedirectHandler().ServeHTTP(rr, req)
	res := rr.Result()
	defer res.Body.Close()

	// Should redirect to Google
	require.Equal(t, http.StatusTemporaryRedirect, res.StatusCode)

	stateCookie := cookieByName(t, res, "oauth_state")
	assert.False(t, stateCookie.Secure, "oauth state cookie should not be Secure")
}
