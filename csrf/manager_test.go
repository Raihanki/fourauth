package csrf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Raihanki/fourauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testNewManager(t *testing.T) *Manager {
	def := core.DefaultCookieConfig()
	m := NewManager(def)
	assert.NotNil(t, m)
	assert.Equal(t, &Manager{cfg: def}, m)

	return m
}

func TestManager_New(t *testing.T) {
	testNewManager(t)
}

func TestManager_Issue(t *testing.T) {
	m := testNewManager(t)
	rr := httptest.NewRecorder()

	token, err := m.Issue(rr)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	resp := rr.Result()
	cookies := resp.Cookies()
	assert.Len(t, cookies, 1)

	csrf := cookies[0]
	assert.NotNil(t, csrf)
	assert.Equal(t, m.cfg.Path, csrf.Path)
	assert.Equal(t, m.cfg.Domain, csrf.Domain)
	assert.Equal(t, false, csrf.HttpOnly)
	assert.Equal(t, m.cfg.Secure, csrf.Secure)
	assert.Equal(t, m.cfg.SameSite, csrf.SameSite)
}

func TestManager_Validate(t *testing.T) {
	t.Run("missing cookie", func(t *testing.T) {
		m := testNewManager(t)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(m.cfg.CSRFHeaderName, "token")

		err := m.Validate(req)
		require.Error(t, err)
		assert.ErrorIs(t, err, core.ErrCSRFTokenMissing)
	})

	t.Run("missing header", func(t *testing.T) {
		m := testNewManager(t)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  m.cfg.CSRFCookieName,
			Value: "token",
		})

		err := m.Validate(req)
		require.Error(t, err)
		assert.ErrorIs(t, err, core.ErrCSRFTokenMissing)
	})

	t.Run("token mismatch", func(t *testing.T) {
		m := testNewManager(t)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  m.cfg.CSRFCookieName,
			Value: "cookie-token",
		})
		req.Header.Set(m.cfg.CSRFHeaderName, "header-token")

		err := m.Validate(req)
		require.Error(t, err)
		assert.ErrorIs(t, err, core.ErrCSRFTokenInvalid)
	})

	t.Run("valid token", func(t *testing.T) {
		m := testNewManager(t)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  m.cfg.CSRFCookieName,
			Value: "same-token",
		})
		req.Header.Set(m.cfg.CSRFHeaderName, "same-token")

		err := m.Validate(req)
		require.NoError(t, err)
	})
}
