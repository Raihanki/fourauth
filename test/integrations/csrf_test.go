package integrations

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Raihanki/fourauth"
	"github.com/Raihanki/fourauth/provider/local"
	"github.com/Raihanki/fourauth/test/integrations/memory"
	"github.com/Raihanki/fourauth/token/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuth_CSRFHandler_Integration(t *testing.T) {
	t.Run("enabled sets csrf cookie", func(t *testing.T) {
		auth := newLocalAuth(t)

		req := httptest.NewRequest(http.MethodGet, "/csrf", nil)
		rr := httptest.NewRecorder()

		auth.CSRFHandler().ServeHTTP(rr, req)

		res := rr.Result()
		defer res.Body.Close()

		assert.Equal(t, http.StatusNoContent, res.StatusCode)

		csrfCookie := cookieByName(t, res, "XSRF-TOKEN")
		assert.NotEmpty(t, csrfCookie.Value)
	})

	t.Run("disabled returns 404", func(t *testing.T) {
		pub, priv, err := jwt.GenerateKeyPair()
		require.NoError(t, err)

		issuer := jwt.New(jwt.Config{
			PrivateKey: priv,
			PublicKey:  pub,
		})

		auth, err := fourauth.New(
			fourauth.WithUserRepository(memory.NewMemUserRepo()),
			fourauth.WithRefreshTokenRepository(memory.NewMemRefreshRepo()),
			fourauth.WithIssuer(issuer),
			fourauth.WithBearerTransport(),
			fourauth.WithLocalAuth(),
			fourauth.WithHasher(local.NewBcrypt()),
		)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/csrf", nil)
		rr := httptest.NewRecorder()

		auth.CSRFHandler().ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
		assert.Contains(t, rr.Body.String(), "csrf is not enabled")
	})
}

func TestAuth_CSRFMiddleware_Integration(t *testing.T) {
	t.Run("disabled is no-op", func(t *testing.T) {
		pub, priv, err := jwt.GenerateKeyPair()
		require.NoError(t, err)

		issuer := jwt.New(jwt.Config{
			PrivateKey: priv,
			PublicKey:  pub,
		})

		auth, err := fourauth.New(
			fourauth.WithUserRepository(memory.NewMemUserRepo()),
			fourauth.WithRefreshTokenRepository(memory.NewMemRefreshRepo()),
			fourauth.WithIssuer(issuer),
			fourauth.WithBearerTransport(),
			fourauth.WithLocalAuth(),
			fourauth.WithHasher(local.NewBcrypt()),
		)
		require.NoError(t, err)

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodPost, "/protected", nil)
		rr := httptest.NewRecorder()

		auth.CSRFMiddleware()(next).ServeHTTP(rr, req)

		assert.True(t, nextCalled)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("enabled blocks missing csrf", func(t *testing.T) {
		auth := newLocalAuth(t)

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodPost, "/protected", nil)
		rr := httptest.NewRecorder()

		auth.CSRFMiddleware()(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled)
		assert.NotEqual(t, http.StatusOK, rr.Code)
	})

	t.Run("enabled allows valid csrf", func(t *testing.T) {
		auth := newLocalAuth(t)

		// first get csrf token
		csrfReq := httptest.NewRequest(http.MethodGet, "/csrf", nil)
		csrfRR := httptest.NewRecorder()
		auth.CSRFHandler().ServeHTTP(csrfRR, csrfReq)

		csrfRes := csrfRR.Result()
		defer csrfRes.Body.Close()

		csrfCookie := cookieByName(t, csrfRes, "XSRF-TOKEN")
		require.NotEmpty(t, csrfCookie.Value)

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodPost, "/protected", nil)
		req.AddCookie(csrfCookie)
		req.Header.Set("X-XSRF-Token", csrfCookie.Value)

		rr := httptest.NewRecorder()
		auth.CSRFMiddleware()(next).ServeHTTP(rr, req)

		assert.True(t, nextCalled)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}
