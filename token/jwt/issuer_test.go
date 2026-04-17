package jwt

import (
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Raihanki/fourauth/core"
)

func newTestIssuer(t *testing.T) *Issuer {
	t.Helper()

	pub, priv, err := GenerateKeyPair()
	require.NoError(t, err)

	return New(Config{
		PrivateKey: priv,
		PublicKey:  pub,
	})
}

func TestNew(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	require.NoError(t, err)

	issuer := New(Config{
		PrivateKey: priv,
		PublicKey:  pub,
	})

	require.NotNil(t, issuer)
	assert.Equal(t, string(priv), string(issuer.privateKey))
	assert.Equal(t, string(pub), string(issuer.publicKey))
}

func TestIssuer_IssueAndParseAccessToken(t *testing.T) {
	issuer := newTestIssuer(t)
	expiresAt := time.Now().Add(15 * time.Minute).UTC()

	gotToken, err := issuer.IssueAccessToken(core.AccessClaims{
		Subject:   "user-123",
		Email:     "user@example.com",
		Role:      "admin",
		ExpiresAt: expiresAt,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, gotToken.Value)
	assert.Equal(t, expiresAt, gotToken.ExpiredAt)

	gotClaims, err := issuer.ParseAccessToken(gotToken.Value)
	require.NoError(t, err)
	require.NotNil(t, gotClaims)
	assert.Equal(t, "user-123", gotClaims.Subject)
	assert.Equal(t, "user@example.com", gotClaims.Email)
	assert.Equal(t, "admin", gotClaims.Role)
}

func TestIssuer_IssueAndParseRefreshToken(t *testing.T) {
	issuer := newTestIssuer(t)
	expiresAt := time.Now().Add(24 * time.Hour).UTC()

	gotToken, err := issuer.IssueRefreshToken(core.RefreshClaims{
		Subject:   "user-123",
		TokenID:   "token-abc",
		ExpiresAt: expiresAt,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, gotToken.Value)
	assert.Equal(t, expiresAt, gotToken.ExpiredAt)

	gotClaims, err := issuer.ParseRefreshToken(gotToken.Value)
	require.NoError(t, err)
	require.NotNil(t, gotClaims)
	assert.Equal(t, "user-123", gotClaims.Subject)
	assert.Equal(t, "token-abc", gotClaims.TokenID)
}

func TestIssuer_ParseAccessToken_InvalidSignature(t *testing.T) {
	issuerA := newTestIssuer(t)
	issuerB := newTestIssuer(t)

	token, err := issuerA.IssueAccessToken(core.AccessClaims{
		Subject:   "user-123",
		Email:     "user@example.com",
		Role:      "admin",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	})
	require.NoError(t, err)

	_, err = issuerB.ParseAccessToken(token.Value)
	assert.Error(t, err)
}

func TestIssuer_ParseRefreshToken_InvalidSignature(t *testing.T) {
	issuerA := newTestIssuer(t)
	issuerB := newTestIssuer(t)

	token, err := issuerA.IssueRefreshToken(core.RefreshClaims{
		Subject:   "user-123",
		TokenID:   "token-abc",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	require.NoError(t, err)

	_, err = issuerB.ParseRefreshToken(token.Value)
	assert.Error(t, err)
}

func TestIssuer_ParseAccessToken_InvalidMethod(t *testing.T) {
	issuer := newTestIssuer(t)

	raw := gjwt.NewWithClaims(gjwt.SigningMethodHS256, gjwt.MapClaims{
		"sub":   "user-123",
		"email": "user@example.com",
		"role":  "admin",
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
	})

	signed, err := raw.SignedString([]byte("secret"))
	require.NoError(t, err)

	_, err = issuer.ParseAccessToken(signed)
	assert.Error(t, err)
}

func TestIssuer_ParseRefreshToken_InvalidMethod(t *testing.T) {
	issuer := newTestIssuer(t)

	raw := gjwt.NewWithClaims(gjwt.SigningMethodHS256, gjwt.MapClaims{
		"sub": "user-123",
		"tid": "token-abc",
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	})

	signed, err := raw.SignedString([]byte("secret"))
	require.NoError(t, err)

	_, err = issuer.ParseRefreshToken(signed)
	assert.Error(t, err)
}

func TestIssuer_Kind(t *testing.T) {
	issuer := newTestIssuer(t)
	assert.Equal(t, core.TokenKindJWT, issuer.Kind())
}
