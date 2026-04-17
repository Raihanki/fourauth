package paseto

import (
	"testing"
	"time"

	libpaseto "aidanwoods.dev/go-paseto"
	"github.com/Raihanki/fourauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestIssuer(t *testing.T) *Issuer {
	t.Helper()

	k, err := GenerateSymmetricKey()
	assert.NoError(t, err)

	i, err := New(k)
	assert.NoError(t, err)

	return i
}

func TestNew(t *testing.T) {
	k, err := GenerateSymmetricKey()
	assert.NoError(t, err)

	i, err := New(k)
	assert.NoError(t, err)
	assert.NotNil(t, i)
}

func TestIssuer_IssueAndParseAccessToken(t *testing.T) {
	issuer := newTestIssuer(t)

	expiresAt := time.Now().Add(15 * time.Minute).UTC()
	want := core.AccessClaims{
		Subject:   "user-123",
		Email:     "user@example.com",
		Role:      "admin",
		ExpiresAt: expiresAt,
	}

	token, err := issuer.IssueAccessToken(want)
	require.NoError(t, err)
	assert.NotEmpty(t, token.Value)
	assert.True(t, token.ExpiredAt.Equal(expiresAt))

	got, err := issuer.ParseAccessToken(token.Value)
	require.NoError(t, err)
	assert.Equal(t, want.Subject, got.Subject)
	assert.Equal(t, want.Email, got.Email)
	assert.Equal(t, want.Role, got.Role)
	assert.Equal(t, want.ExpiresAt.Unix(), got.ExpiresAt.Unix())
}

func TestIssuer_IssueAndParseRefreshToken(t *testing.T) {
	issuer := newTestIssuer(t)

	expiresAt := time.Now().Add(24 * time.Hour).UTC()
	want := core.RefreshClaims{
		Subject:   "user-123",
		TokenID:   "refresh-token-id",
		ExpiresAt: expiresAt,
	}

	token, err := issuer.IssueRefreshToken(want)
	require.NoError(t, err)
	assert.NotEmpty(t, token.Value)
	assert.True(t, token.ExpiredAt.Equal(expiresAt))

	got, err := issuer.ParseRefreshToken(token.Value)
	require.NoError(t, err)
	assert.Equal(t, want.Subject, got.Subject)
	assert.Equal(t, want.TokenID, got.TokenID)
	assert.Equal(t, want.ExpiresAt.Unix(), got.ExpiresAt.Unix())
}

func TestIssuer_ParseAccessToken_InvalidToken(t *testing.T) {
	issuer := newTestIssuer(t)

	got, err := issuer.ParseAccessToken("not-a-valid-token")
	require.Error(t, err)
	assert.Equal(t, core.ErrInvalidToken, err)
	assert.Equal(t, core.AccessClaims{}, got)
}

func TestIssuer_ParseRefreshToken_InvalidToken(t *testing.T) {
	issuer := newTestIssuer(t)

	got, err := issuer.ParseRefreshToken("not-a-valid-token")
	require.Error(t, err)
	assert.Equal(t, core.ErrInvalidToken, err)
	assert.Equal(t, core.RefreshClaims{}, got)
}

func TestIssuer_ParseAccessToken_WrongKey(t *testing.T) {
	issuerA := newTestIssuer(t)
	issuerB := newTestIssuer(t)

	token, err := issuerA.IssueAccessToken(core.AccessClaims{
		Subject:   "user-123",
		Email:     "user@example.com",
		Role:      "admin",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	})
	require.NoError(t, err)

	got, err := issuerB.ParseAccessToken(token.Value)
	require.Error(t, err)
	assert.Equal(t, core.ErrInvalidToken, err)
	assert.Equal(t, core.AccessClaims{}, got)
}

func TestIssuer_ParseRefreshToken_WrongKey(t *testing.T) {
	issuerA := newTestIssuer(t)
	issuerB := newTestIssuer(t)

	token, err := issuerA.IssueRefreshToken(core.RefreshClaims{
		Subject:   "user-123",
		TokenID:   "refresh-token-id",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	require.NoError(t, err)

	got, err := issuerB.ParseRefreshToken(token.Value)
	require.Error(t, err)
	assert.Equal(t, core.ErrInvalidToken, err)
	assert.Equal(t, core.RefreshClaims{}, got)
}

func TestIssuer_ParseAccessToken_MissingClaims(t *testing.T) {
	issuer := newTestIssuer(t)

	tok := libpaseto.NewToken()
	tok.SetSubject("user-123")
	tok.SetExpiration(time.Now().Add(15 * time.Minute))
	tok.SetIssuedAt(time.Now())

	raw := tok.V4Encrypt(issuer.key, nil)

	got, err := issuer.ParseAccessToken(raw)
	require.Error(t, err)
	assert.Equal(t, core.ErrInvalidToken, err)
	assert.Equal(t, core.AccessClaims{}, got)
}

func TestIssuer_ParseRefreshToken_MissingClaims(t *testing.T) {
	issuer := newTestIssuer(t)

	tok := libpaseto.NewToken()
	tok.SetSubject("user-123")
	tok.SetExpiration(time.Now().Add(15 * time.Minute))
	tok.SetIssuedAt(time.Now())

	raw := tok.V4Encrypt(issuer.key, nil)

	got, err := issuer.ParseRefreshToken(raw)
	require.Error(t, err)
	assert.Equal(t, core.ErrInvalidToken, err)
	assert.Equal(t, core.RefreshClaims{}, got)
}

func TestIssuer_ParseAccessToken_ExpiredToken(t *testing.T) {
	issuer := newTestIssuer(t)

	token, err := issuer.IssueAccessToken(core.AccessClaims{
		Subject:   "user-123",
		Email:     "user@example.com",
		Role:      "admin",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})
	require.NoError(t, err)

	got, err := issuer.ParseAccessToken(token.Value)
	require.Error(t, err)
	assert.Equal(t, core.ErrInvalidToken, err)
	assert.Equal(t, core.AccessClaims{}, got)
}

func TestIssuer_ParseRefreshToken_ExpiredToken(t *testing.T) {
	issuer := newTestIssuer(t)

	token, err := issuer.IssueRefreshToken(core.RefreshClaims{
		Subject:   "user-123",
		TokenID:   "refresh-token-id",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})
	require.NoError(t, err)

	got, err := issuer.ParseRefreshToken(token.Value)
	require.Error(t, err)
	assert.Equal(t, core.ErrInvalidToken, err)
	assert.Equal(t, core.RefreshClaims{}, got)
}

func TestIssuer_Kind(t *testing.T) {
	issuer := newTestIssuer(t)
	assert.Equal(t, core.TokenKindPaseto, issuer.Kind())
}
