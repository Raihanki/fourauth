package bearer

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Raihanki/fourauth/core"
	"github.com/stretchr/testify/assert"
)

func newTestTransport(t *testing.T) *Transport {
	transport := New()
	assert.NotNil(t, transport)
	assert.Equal(t, &Transport{}, transport)

	return transport
}

func TestNew(t *testing.T) {
	newTestTransport(t)
}

func TestTransport_WriteTokens(t *testing.T) {
	tr := newTestTransport(t)
	rr := httptest.NewRecorder()

	err := tr.WriteTokens(rr, core.TokenPair{
		AccessToken: core.Token{
			Value:     "access-token",
			ExpiredAt: time.Now().Add(time.Hour),
		},
		RefreshToken: core.Token{
			Value:     "access-token",
			ExpiredAt: time.Now().Add(time.Hour * 2),
		},
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, core.ErrUnsupportedWriteTokens)
}

func TestTransport_ReadAccessToken(t *testing.T) {
	tr := newTestTransport(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Add("Authorization", "Bearer access-token")

	res, err := tr.ReadAccessToken(req)
	assert.NoError(t, err)
	assert.NotEmpty(t, res)
	assert.Equal(t, "access-token", res)
}

func TestTransport_ReadRefreshToken(t *testing.T) {
	tr := newTestTransport(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)

	res, err := tr.ReadRefreshToken(req)
	assert.Error(t, err)
	assert.Empty(t, res)
	assert.ErrorIs(t, err, core.ErrUnsupportedRefreshRead)
}

func TestTransport_ReadAccessToken_MissingAuthorizationHeader(t *testing.T) {
	tr := newTestTransport(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)

	res, err := tr.ReadAccessToken(req)
	assert.Error(t, err)
	assert.Empty(t, res)
	assert.ErrorIs(t, err, core.ErrMissingAuthorizationHeader)
}

func TestTransport_ReadAccessToken_MissingInvalidHeader(t *testing.T) {
	tr := newTestTransport(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Add("Authorization", "access-token")

	res, err := tr.ReadAccessToken(req)
	assert.Error(t, err)
	assert.Empty(t, res)
	assert.ErrorIs(t, err, core.ErrMissingAuthorizationHeader)
}

func TestTransport_Clear(t *testing.T) {
	tr := newTestTransport(t)
	rr := httptest.NewRecorder()

	err := tr.Clear(rr)
	assert.Error(t, err)
	assert.ErrorIs(t, err, core.ErrUnsupportedClear)
}

func TestTransport_Kind(t *testing.T) {
	tr := newTestTransport(t)
	assert.Equal(t, core.TransportKindBearer, tr.Kind())
}
