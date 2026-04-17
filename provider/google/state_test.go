package google

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Raihanki/fourauth/core"
)

func TestNewState(t *testing.T) {
	store := NewState()

	require.NotNil(t, store)
	assert.Equal(t, "oauth_state", store.CookieName)
	assert.Equal(t, "/", store.Path)
	assert.True(t, store.Secure)
	assert.Equal(t, http.SameSiteLaxMode, store.SameSite)
	assert.Equal(t, 10*time.Minute, store.MaxAge)
	assert.Empty(t, store.Domain)
}

func TestStateStore_Issue(t *testing.T) {
	store := NewState()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	state, err := store.Issue(rr, req)
	require.NoError(t, err)
	assert.NotEmpty(t, state)

	resp := rr.Result()
	cookies := resp.Cookies()
	require.Len(t, cookies, 1)

	c := cookies[0]
	assert.Equal(t, store.CookieName, c.Name)
	assert.Equal(t, state, c.Value)
	assert.Equal(t, store.Path, c.Path)
	assert.Equal(t, store.Domain, c.Domain)
	assert.True(t, c.HttpOnly)
	assert.Equal(t, store.Secure, c.Secure)
	assert.Equal(t, store.SameSite, c.SameSite)
	assert.Equal(t, int(store.MaxAge.Seconds()), c.MaxAge)
}

func TestStateStore_Verify(t *testing.T) {
	store := NewState()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  store.CookieName,
		Value: "valid-state",
	})

	err := store.Verify(req, "valid-state")
	require.NoError(t, err)
}

func TestStateStore_Verify_EmptyState(t *testing.T) {
	store := NewState()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	err := store.Verify(req, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, core.ErrStateMissing)
}

func TestStateStore_Verify_MissingCookie(t *testing.T) {
	store := NewState()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	err := store.Verify(req, "some-state")
	require.Error(t, err)
	assert.ErrorIs(t, err, core.ErrStateMissing)
}

func TestStateStore_Verify_EmptyCookieValue(t *testing.T) {
	store := NewState()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  store.CookieName,
		Value: "",
	})

	err := store.Verify(req, "some-state")
	require.Error(t, err)
	assert.ErrorIs(t, err, core.ErrStateMissing)
}

func TestStateStore_Verify_InvalidState(t *testing.T) {
	store := NewState()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  store.CookieName,
		Value: "stored-state",
	})

	err := store.Verify(req, "different-state")
	require.Error(t, err)
	assert.ErrorIs(t, err, core.ErrStateInvalid)
}

func TestStateStore_Clear(t *testing.T) {
	store := NewState()
	rr := httptest.NewRecorder()

	store.Clear(rr)

	resp := rr.Result()
	cookies := resp.Cookies()
	require.Len(t, cookies, 1)

	c := cookies[0]
	assert.Equal(t, store.CookieName, c.Name)
	assert.Empty(t, c.Value)
	assert.Equal(t, store.Path, c.Path)
	assert.Equal(t, store.Domain, c.Domain)
	assert.True(t, c.HttpOnly)
	assert.Equal(t, store.Secure, c.Secure)
	assert.Equal(t, store.SameSite, c.SameSite)
	assert.Equal(t, -1, c.MaxAge)
}

func TestStateStore_newState(t *testing.T) {
	store := NewState()

	state1, err := store.newState()
	require.NoError(t, err)
	assert.NotEmpty(t, state1)

	state2, err := store.newState()
	require.NoError(t, err)
	assert.NotEmpty(t, state2)

	assert.NotEqual(t, state1, state2)
}
