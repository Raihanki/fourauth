package google

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Raihanki/fourauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type mockExchanger struct {
	token *oauth2.Token
	err   error
}

func (m *mockExchanger) Exchange(ctx context.Context, code string, _ ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return m.token, m.err
}

func TestProvider_Exchange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"sub":"google-123",
			"email":"user@example.com",
			"name":"Gaou",
			"picture":"https://example.com/avatar.png",
			"email_verified":true
		}`))
	}))
	defer server.Close()

	token := &oauth2.Token{
		AccessToken: "token-123",
		TokenType:   "Bearer",
	}

	p := &Provider{
		cfg: &mockExchanger{token: token},
		client: func(ctx context.Context, tok *oauth2.Token) *http.Client {
			return server.Client()
		},
		userInfoURL: server.URL,
	}

	got, err := p.Exchange(context.Background(), "auth-code")

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, string(core.ProviderGoogle), got.Provider)
	assert.Equal(t, "google-123", got.ProviderID)
	assert.Equal(t, "user@example.com", got.Email)
	assert.Equal(t, "Gaou", got.Name)
	assert.Equal(t, "https://example.com/avatar.png", got.AvatarURL)
	assert.True(t, got.EmailVerified)
}

func TestProvider_Exchange_TokenExchangeError(t *testing.T) {
	p := &Provider{
		cfg: &mockExchanger{err: assert.AnError},
		client: func(ctx context.Context, tok *oauth2.Token) *http.Client {
			return http.DefaultClient
		},
		userInfoURL: "http://example.com",
	}

	got, err := p.Exchange(context.Background(), "auth-code")

	require.Error(t, err)
	assert.Equal(t, core.ExternalIdentity{}, got)
}

func TestProvider_Exchange_UserInfoStatusNotOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer server.Close()

	token := &oauth2.Token{AccessToken: "token-123"}

	p := &Provider{
		cfg: &mockExchanger{token: token},
		client: func(ctx context.Context, tok *oauth2.Token) *http.Client {
			return server.Client()
		},
		userInfoURL: server.URL,
	}

	got, err := p.Exchange(context.Background(), "auth-code")

	require.Error(t, err)
	assert.Equal(t, core.ExternalIdentity{}, got)
	assert.Contains(t, err.Error(), "google userinfo returned status 401")
}

func TestProvider_Exchange_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid-json`))
	}))
	defer server.Close()

	token := &oauth2.Token{AccessToken: "token-123"}

	p := &Provider{
		cfg: &mockExchanger{token: token},
		client: func(ctx context.Context, tok *oauth2.Token) *http.Client {
			return server.Client()
		},
		userInfoURL: server.URL,
	}

	got, err := p.Exchange(context.Background(), "auth-code")

	require.Error(t, err)
	assert.Empty(t, got)
}

func TestProvider_UserFromGoogleToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"sub":"google-123",
			"email":"user@example.com",
			"name":"Gaou",
			"picture":"https://example.com/avatar.png",
			"email_verified":true
		}`))
	}))
	defer server.Close()

	token := &oauth2.Token{AccessToken: "secret"}

	p := &Provider{
		cfg: &mockExchanger{token: token},
		client: func(ctx context.Context, tok *oauth2.Token) *http.Client {
			return server.Client()
		},
		userInfoURL: server.URL,
	}

	got, err := p.UserFromGoogleToken(context.Background(), "secret")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, string(core.ProviderGoogle), got.Provider)
	assert.Equal(t, "google-123", got.ProviderID)
	assert.Equal(t, "user@example.com", got.Email)
	assert.Equal(t, "Gaou", got.Name)
	assert.Equal(t, "https://example.com/avatar.png", got.AvatarURL)
	assert.True(t, got.EmailVerified)
}

func TestProvider_Name(t *testing.T) {
	p := &Provider{}
	assert.Equal(t, core.ProviderGoogle, p.Name())
}
