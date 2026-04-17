package cookie

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Raihanki/fourauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestTransport(t *testing.T) *Transport {
	transport := New(core.DefaultCookieConfig())
	assert.NotEmpty(t, transport)
	assert.Equal(t, core.DefaultCookieConfig(), transport.cfg)

	return transport
}

func TestNew(t *testing.T) {
	newTestTransport(t)
}

func TestTransport_WriteTokens(t *testing.T) {
	tr := newTestTransport(t)
	rr := httptest.NewRecorder()

	accessExp := time.Now().Add(15 * time.Minute)
	refreshExp := time.Now().Add(24 * time.Hour)

	pair := core.TokenPair{
		AccessToken: core.Token{
			Value:     "access-value",
			ExpiredAt: accessExp,
		},
		RefreshToken: core.Token{
			Value:     "refresh-value",
			ExpiredAt: refreshExp,
		},
	}

	err := tr.WriteTokens(rr, pair)
	require.NoError(t, err)

	resp := rr.Result()
	cookies := resp.Cookies()
	require.Len(t, cookies, 2)

	var accessCookie, refreshCookie *http.Cookie
	for _, c := range cookies {
		switch c.Name {
		case tr.cfg.AccessCookieName:
			accessCookie = c
		case tr.cfg.RefreshCookieName:
			refreshCookie = c
		}
	}

	require.NotNil(t, accessCookie)
	require.NotNil(t, refreshCookie)

	assert.Equal(t, "access-value", accessCookie.Value)
	assert.Equal(t, tr.cfg.Path, accessCookie.Path)
	assert.Equal(t, tr.cfg.Domain, accessCookie.Domain)
	assert.Equal(t, tr.cfg.HTTPOnly, accessCookie.HttpOnly)
	assert.Equal(t, tr.cfg.Secure, accessCookie.Secure)
	assert.Equal(t, tr.cfg.SameSite, accessCookie.SameSite)
	assert.Equal(t, accessExp.Unix(), accessCookie.Expires.Unix())
	assert.GreaterOrEqual(t, accessCookie.MaxAge, 0)

	assert.Equal(t, "refresh-value", refreshCookie.Value)
	assert.Equal(t, tr.cfg.Path, refreshCookie.Path)
	assert.Equal(t, tr.cfg.Domain, refreshCookie.Domain)
	assert.Equal(t, tr.cfg.HTTPOnly, refreshCookie.HttpOnly)
	assert.Equal(t, tr.cfg.Secure, refreshCookie.Secure)
	assert.Equal(t, tr.cfg.SameSite, refreshCookie.SameSite)
	assert.Equal(t, refreshExp.Unix(), refreshCookie.Expires.Unix())
	assert.GreaterOrEqual(t, refreshCookie.MaxAge, 0)
}

func TestTransport_ReadAccessToken(t *testing.T) {
	tr := newTestTransport(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  tr.cfg.AccessCookieName,
		Value: "access-value",
	})

	token, err := tr.ReadAccessToken(req)
	require.NoError(t, err)
	assert.Equal(t, "access-value", token)
}

func TestTransport_ReadAccessToken_MissingCookie(t *testing.T) {
	tr := newTestTransport(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	token, err := tr.ReadAccessToken(req)
	require.Error(t, err)
	assert.Empty(t, token)
}

func TestTransport_ReadRefreshToken(t *testing.T) {
	tr := newTestTransport(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  tr.cfg.RefreshCookieName,
		Value: "refresh-value",
	})

	token, err := tr.ReadRefreshToken(req)
	require.NoError(t, err)
	assert.Equal(t, "refresh-value", token)
}

func TestTransport_ReadRefreshToken_MissingCookie(t *testing.T) {
	tr := newTestTransport(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	token, err := tr.ReadRefreshToken(req)
	require.Error(t, err)
	assert.Empty(t, token)
}

func TestTransport_Clear(t *testing.T) {
	tr := newTestTransport(t)
	rr := httptest.NewRecorder()

	err := tr.Clear(rr)
	require.NoError(t, err)

	resp := rr.Result()
	cookies := resp.Cookies()
	require.Len(t, cookies, 2)

	for _, c := range cookies {
		assert.Contains(t, []string{tr.cfg.AccessCookieName, tr.cfg.RefreshCookieName}, c.Name)
		assert.Equal(t, "", c.Value)
		assert.Equal(t, tr.cfg.Path, c.Path)
		assert.Equal(t, tr.cfg.Domain, c.Domain)
		assert.Equal(t, -1, c.MaxAge)
		assert.Equal(t, tr.cfg.HTTPOnly, c.HttpOnly)
		assert.Equal(t, tr.cfg.Secure, c.Secure)
		assert.Equal(t, tr.cfg.SameSite, c.SameSite)
	}
}

func TestMaxAgeFrom(t *testing.T) {
	t.Run("future time", func(t *testing.T) {
		exp := time.Now().Add(10 * time.Second)
		got := maxAgeFrom(exp)
		assert.GreaterOrEqual(t, got, 0)
		assert.LessOrEqual(t, got, 10)
	})

	t.Run("past time", func(t *testing.T) {
		exp := time.Now().Add(-10 * time.Second)
		got := maxAgeFrom(exp)
		assert.Equal(t, 0, got)
	})
}

func TestTransport_Kind(t *testing.T) {
	tr := newTestTransport(t)
	assert.Equal(t, core.TransportKindCookie, tr.Kind())
}
