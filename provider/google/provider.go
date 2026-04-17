package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Raihanki/fourauth/core"
	"golang.org/x/oauth2"
)

type exchanger interface {
	Exchange(context.Context, string, ...oauth2.AuthCodeOption) (*oauth2.Token, error)
}

type httpClientProvider func(context.Context, *oauth2.Token) *http.Client

// Provider is an ExternalProvider for Google OAuth2.
type Provider struct {
	cfg         exchanger
	client      httpClientProvider
	userInfoURL string
}

// NewProvider creates a new Google OAuth2 Provider.
func NewProvider(cfg *core.GoogleConfig, state *StateStore) *Provider {
	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
	}

	return &Provider{
		cfg:         oauthCfg,
		client:      oauthCfg.Client,
		userInfoURL: "https://openidconnect.googleapis.com/v1/userinfo",
	}
}

func (p *Provider) Name() core.ProviderName {
	return core.ProviderGoogle
}

func (p *Provider) AuthCodeURL(state string) string {
	if c, ok := p.cfg.(*oauth2.Config); ok {
		return c.AuthCodeURL(state)
	}
	return ""
}

func (p *Provider) Exchange(ctx context.Context, code string) (core.ExternalIdentity, error) {
	token, err := p.cfg.Exchange(ctx, code)
	if err != nil {
		return core.ExternalIdentity{}, err
	}

	c := p.client(ctx, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userInfoURL, nil)
	if err != nil {
		return core.ExternalIdentity{}, err
	}

	resp, err := c.Do(req)
	if err != nil {
		return core.ExternalIdentity{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return core.ExternalIdentity{}, fmt.Errorf("google userinfo returned status %d", resp.StatusCode)
	}

	var profile Profile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return core.ExternalIdentity{}, err
	}

	return core.ExternalIdentity{
		Provider:      string(core.ProviderGoogle),
		ProviderID:    profile.Sub,
		Email:         profile.Email,
		Name:          profile.Name,
		AvatarURL:     profile.Picture,
		EmailVerified: profile.EmailVerified,
	}, nil
}

func (p *Provider) UserFromGoogleToken(ctx context.Context, accessToken string) (core.ExternalIdentity, error) {
	token := &oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
	}

	client := p.client(ctx, token)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		p.userInfoURL,
		nil,
	)
	if err != nil {
		return core.ExternalIdentity{}, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return core.ExternalIdentity{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return core.ExternalIdentity{}, fmt.Errorf("google userinfo returned status: %s", resp.Status)
	}

	var profile Profile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return core.ExternalIdentity{}, err
	}

	return core.ExternalIdentity{
		Provider:      string(core.ProviderGoogle),
		ProviderID:    profile.Sub,
		Email:         profile.Email,
		Name:          profile.Name,
		AvatarURL:     profile.Picture,
		EmailVerified: profile.EmailVerified,
	}, nil
}
