package integrations

import (
	"testing"

	"github.com/Raihanki/fourauth"
	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/provider/local"
	"github.com/Raihanki/fourauth/test/integrations/memory"
	"github.com/Raihanki/fourauth/token/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newAuthGoogle(t *testing.T) *fourauth.Auth {
	t.Helper()

	clientId := GOOGLE_CLIENT_ID
	clientSecret := GOOGLE_CLIENT_SECRET
	redirectURL := GOOGLE_REDIRECT_URL

	pub, priv, err := jwt.GenerateKeyPair()
	assert.NoError(t, err)

	issuer := jwt.New(jwt.Config{
		PrivateKey: priv,
		PublicKey:  pub,
	})

	auth, err := fourauth.New(
		fourauth.WithUserRepository(memory.NewMemUserRepo()),
		fourauth.WithRefreshTokenRepository(memory.NewMemRefreshRepo()),
		fourauth.WithIssuer(issuer),
		fourauth.WithCookieTransport(),
		fourauth.WithGoogleAuth(core.GoogleConfig{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
		}),
	)
	require.NoError(t, err)

	return auth
}

func newLocalAuth(t *testing.T) *fourauth.Auth {
	t.Helper()

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
		fourauth.WithCookieTransport(),
		fourauth.WithLocalAuth(),
		fourauth.WithHasher(local.NewBcrypt()),
	)
	require.NoError(t, err)

	return auth
}

func newLocalAuthWithoutRefresh(t *testing.T) *fourauth.Auth {
	t.Helper()

	pub, priv, err := jwt.GenerateKeyPair()
	require.NoError(t, err)

	issuer := jwt.New(jwt.Config{
		PrivateKey: priv,
		PublicKey:  pub,
	})

	auth, err := fourauth.New(
		fourauth.WithUserRepository(memory.NewMemUserRepo()),
		fourauth.WithIssuer(issuer),
		fourauth.WithCookieTransport(),
		fourauth.WithLocalAuth(),
		fourauth.WithHasher(local.NewBcrypt()),
		fourauth.WithoutRefreshToken(),
	)
	require.NoError(t, err)

	return auth
}
