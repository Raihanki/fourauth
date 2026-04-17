package core

import (
	"net/http"
	"time"
)

// TokenConfig holds configuration settings for access and refresh tokens.
type TokenConfig struct {
	Issuer          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

// CookieConfig holds configuration settings for cookies used in token transport.
// This includes cookie names, security settings, and CSRF protection settings.
type CookieConfig struct {
	AccessCookieName  string
	RefreshCookieName string
	Domain            string
	Path              string
	Secure            bool
	HTTPOnly          bool
	SameSite          http.SameSite
	EnableCSRF        bool
	CSRFCookieName    string
	CSRFHeaderName    string
}

// BearerConfig holds configuration settings for Bearer token transport
// when using request body for refresh token exchange.
type BearerConfig struct {
	RefreshBodyField string
}

// GoogleConfig holds OAuth2 configuration for Google provider.
type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// DefaultTokenConfig returns a default TokenConfig with standard settings:
// 15 minute access token TTL, 7 day refresh token TTL, and "fourauth" as issuer.
func DefaultTokenConfig() TokenConfig {
	return TokenConfig{
		Issuer:          "fourauth",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
	}
}

// DefaultCookieConfig returns a default CookieConfig with secure defaults:
// HTTPOnly cookies, SameSiteLaxMode, CSRF protection enabled.
func DefaultCookieConfig() CookieConfig {
	return CookieConfig{
		AccessCookieName:  "access_token",
		RefreshCookieName: "refresh_token",
		Path:              "/",
		Secure:            true,
		HTTPOnly:          true,
		SameSite:          http.SameSiteLaxMode,
		EnableCSRF:        true,
		CSRFCookieName:    "XSRF-TOKEN",
		CSRFHeaderName:    "X-XSRF-Token",
	}
}
