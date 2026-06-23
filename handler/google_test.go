package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/provider/google"
	"github.com/Raihanki/fourauth/service"
	"github.com/Raihanki/fourauth/test/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type testUser struct {
	id            string
	email         string
	passwordHash  *string
	provider      string
	providerID    *string
	role          string
	emailVerified bool
}

func (u testUser) GetID() string            { return u.id }
func (u testUser) GetEmail() string         { return u.email }
func (u testUser) GetPasswordHash() *string { return u.passwordHash }
func (u testUser) GetProvider() string      { return u.provider }
func (u testUser) GetProviderID() *string   { return u.providerID }
func (u testUser) GetRole() string          { return u.role }
func (u testUser) IsEmailVerified() bool    { return u.emailVerified }

func setupGoogleHandlerTest(t *testing.T) (
	*mocks.UserRepository,
	*mocks.RefreshTokenRepository,
	*mocks.Issuer,
	*mocks.GoogleProvider,
	*mocks.Transport,
	core.ExternalIdentity,
	testUser,
) {
	t.Helper()

	identity := core.ExternalIdentity{
		Provider:      string(core.ProviderGoogle),
		ProviderID:    "google-123",
		Email:         "user@example.com",
		Name:          "Test User",
		AvatarURL:     "https://example.com/avatar.png",
		EmailVerified: true,
	}

	user := testUser{
		id:            "user-1",
		email:         identity.Email,
		provider:      identity.Provider,
		role:          "user",
		emailVerified: identity.EmailVerified,
	}

	return new(mocks.UserRepository), new(mocks.RefreshTokenRepository), new(mocks.Issuer), new(mocks.GoogleProvider), new(mocks.Transport), identity, user
}

func buildService(
	t *testing.T,
	userRepo *mocks.UserRepository,
	refreshRepo *mocks.RefreshTokenRepository,
	issuer *mocks.Issuer,
	googleProv *mocks.GoogleProvider,
	transport *mocks.Transport,
	identity core.ExternalIdentity,
	user testUser,
) *service.Service {
	t.Helper()

	googleProv.
		On("Exchange", mock.Anything, "test-code").
		Return(identity, nil).
		Once()

	userRepo.
		On("GetByProvider", mock.Anything, identity.Provider, identity.ProviderID).
		Return(user, nil).
		Once()

	issuer.
		On("IssueAccessToken", mock.MatchedBy(func(c core.AccessClaims) bool {
			return c.Subject == user.GetID() &&
				c.Email == user.GetEmail() &&
				c.Role == user.GetRole() &&
				!c.ExpiresAt.IsZero()
		})).
		Return(core.Token{
			Value:     "access-token-value",
			ExpiredAt: time.Now().Add(15 * time.Minute),
		}, nil).
		Once()

	issuer.
		On("IssueRefreshToken", mock.MatchedBy(func(c core.RefreshClaims) bool {
			return c.Subject == user.GetID() &&
				c.TokenID != "" &&
				!c.ExpiresAt.IsZero()
		})).
		Return(core.Token{
			Value:     "refresh-token-value",
			ExpiredAt: time.Now().Add(24 * time.Hour),
		}, nil).
		Once()

	transport.
		On("Kind").
		Return(core.TransportKindCookie)

	transport.
		On("WriteTokens", mock.Anything, mock.MatchedBy(func(pair core.TokenPair) bool {
			return pair.AccessToken.Value == "access-token-value" &&
				pair.RefreshToken.Value == "refresh-token-value"
		})).
		Return(nil).
		Once()

	return service.New(
		&core.TokenConfig{
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 24 * time.Hour,
		},
		userRepo,
		refreshRepo,
		issuer,
		transport,
		nil,
		nil,
		googleProv,
		true,
	)
}

func TestGoogleHandler_Callback_WithFrontendRedirect(t *testing.T) {
	userRepo, refreshRepo, issuer, googleProv, transport, identity, user := setupGoogleHandlerTest(t)
	svc := buildService(t, userRepo, refreshRepo, issuer, googleProv, transport, identity, user)

	stateStore := google.NewState()

	issueReq := httptest.NewRequest(http.MethodGet, "/auth/google", nil)
	issueW := httptest.NewRecorder()
	state, err := stateStore.Issue(issueW, issueReq)
	require.NoError(t, err)

	issueResp := issueW.Result()
	defer issueResp.Body.Close()

	var stateCookie *http.Cookie
	for _, c := range issueResp.Cookies() {
		if c.Name == "oauth_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie)

	callbackReq := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=test-code&state="+state, nil)
	callbackReq.AddCookie(stateCookie)
	callbackW := httptest.NewRecorder()

	h := GoogleHandler{
		Service:             svc,
		State:               stateStore,
		Transport:           transport,
		FrontendRedirectURL: "https://myapp.com/dashboard",
	}
	h.Callback(callbackW, callbackReq)

	result := callbackW.Result()
	defer result.Body.Close()

	assert.Equal(t, http.StatusTemporaryRedirect, result.StatusCode)
	assert.Equal(t, "https://myapp.com/dashboard", result.Header.Get("Location"))

	googleProv.AssertExpectations(t)
	userRepo.AssertExpectations(t)
	issuer.AssertExpectations(t)
	transport.AssertExpectations(t)
}

func TestGoogleHandler_Callback_NoFrontendRedirect(t *testing.T) {
	userRepo, refreshRepo, issuer, googleProv, transport, identity, user := setupGoogleHandlerTest(t)
	svc := buildService(t, userRepo, refreshRepo, issuer, googleProv, transport, identity, user)

	stateStore := google.NewState()

	issueReq := httptest.NewRequest(http.MethodGet, "/auth/google", nil)
	issueW := httptest.NewRecorder()
	state, err := stateStore.Issue(issueW, issueReq)
	require.NoError(t, err)

	issueResp := issueW.Result()
	defer issueResp.Body.Close()

	var stateCookie *http.Cookie
	for _, c := range issueResp.Cookies() {
		if c.Name == "oauth_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie)

	callbackReq := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=test-code&state="+state, nil)
	callbackReq.AddCookie(stateCookie)
	callbackW := httptest.NewRecorder()

	h := GoogleHandler{
		Service:   svc,
		State:     stateStore,
		Transport: transport,
	}
	h.Callback(callbackW, callbackReq)

	result := callbackW.Result()
	defer result.Body.Close()

	assert.Equal(t, http.StatusOK, result.StatusCode)
	assert.Empty(t, result.Header.Get("Location"))

	googleProv.AssertExpectations(t)
	userRepo.AssertExpectations(t)
	issuer.AssertExpectations(t)
	transport.AssertExpectations(t)
}
