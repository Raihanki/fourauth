package fourauth

import (
	"errors"

	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/csrf"
	"github.com/Raihanki/fourauth/provider"
	googleprovider "github.com/Raihanki/fourauth/provider/google"
	"github.com/Raihanki/fourauth/provider/local"
	localprovider "github.com/Raihanki/fourauth/provider/local"
	"github.com/Raihanki/fourauth/token"
	transportpkg "github.com/Raihanki/fourauth/transport"
	bearertransport "github.com/Raihanki/fourauth/transport/bearer"
	cookietransport "github.com/Raihanki/fourauth/transport/cookie"
)

// Option configures an Auth instance.
// Options are applied in the order they are provided.
type Option func(*options) error

type options struct {
	tokenCfg       core.TokenConfig
	repo           core.UserRepository
	refreshRepo    core.RefreshTokenRepository
	issuer         token.Issuer
	transport      transportpkg.Transport
	cookieCfg      *core.CookieConfig
	csrfManager    *csrf.Manager
	googleCfg      *core.GoogleConfig
	googleState    *googleprovider.StateStore
	localProvider  provider.PasswordProvider
	googleProvider provider.ExternalProvider
	hasher         localprovider.Hasher

	enableLocal  bool
	enableGoogle bool
}

func defaultOptions() *options {
	cookieCfg := core.DefaultCookieConfig()

	return &options{
		tokenCfg:  core.DefaultTokenConfig(),
		cookieCfg: &cookieCfg,
	}
}

// WithUserRepository sets the user repository.
// Required.
func WithUserRepository(repo core.UserRepository) Option {
	return func(o *options) error {
		o.repo = repo
		return nil
	}
}

// WithRefreshTokenRepository sets the refresh token repository.
// Required.
func WithRefreshTokenRepository(repo core.RefreshTokenRepository) Option {
	return func(o *options) error {
		o.refreshRepo = repo
		return nil
	}
}

// WithTokenConfig sets the token configuration (TTL, issuer).
// Defaults to DefaultTokenConfig() if not set.
func WithTokenConfig(cfg core.TokenConfig) Option {
	return func(o *options) error {
		o.tokenCfg = cfg
		return nil
	}
}

// WithIssuer sets the token issuer.
// Required. Use token.NewJWT or token.NewPaseto to create one.
func WithIssuer(issuer token.Issuer) Option {
	return func(o *options) error {
		o.issuer = issuer
		return nil
	}
}

// WithCookieTransport configures cookie-based token transport.
// Uses DefaultCookieConfig() if no config is provided.
// Automatically enables CSRF protection.
func WithCookieTransport(cfg ...core.CookieConfig) Option {
	return func(o *options) error {
		if len(cfg) > 0 {
			o.cookieCfg = &cfg[0]
		}
		o.transport = cookietransport.New(*o.cookieCfg)
		return nil
	}
}

// WithBearerTransport configures Bearer token transport.
// Uses Authorization header for access tokens and request body for refresh tokens.
// CSRF protection is not available with this transport.
func WithBearerTransport() Option {
	return func(o *options) error {
		o.transport = bearertransport.New()
		return nil
	}
}

// WithCSRFManager sets a custom CSRF manager.
// Only valid with cookie transport.
func WithCSRFManager(m *csrf.Manager) Option {
	return func(o *options) error {
		o.csrfManager = m
		return nil
	}
}

// WithLocalAuth enables email/password authentication.
// Uses bcrypt for password hashing by default.
func WithLocalAuth() Option {
	return func(o *options) error {
		o.enableLocal = true
		return nil
	}
}

// WithLocalProvider sets a custom local auth provider.
func WithLocalProvider(p *localprovider.Provider) Option {
	return func(o *options) error {
		o.enableLocal = true
		o.localProvider = p
		return nil
	}
}

// WithGoogleAuth enables Google OAuth2 authentication.
// Requires GoogleConfig with ClientID, ClientSecret, and RedirectURL.
func WithGoogleAuth(cfg core.GoogleConfig) Option {
	return func(o *options) error {
		o.googleCfg = &cfg
		o.enableGoogle = true
		return nil
	}
}

// WithGoogleProvider sets a custom Google auth provider.
func WithGoogleProvider(p *googleprovider.Provider) Option {
	return func(o *options) error {
		o.enableGoogle = true
		o.googleProvider = p
		return nil
	}
}

// WithHasher sets the password hasher for local auth.
// Defaults to bcrypt if not set.
func WithHasher(h local.Hasher) Option {
	return func(o *options) error {
		o.hasher = h
		return nil
	}
}

func validateOptions(o *options) error {
	if o.repo == nil {
		return errors.New("fourauth: user repository is required")
	}

	if o.refreshRepo == nil {
		return errors.New("fourauth: refresh token repository is required")
	}

	if o.issuer == nil {
		return errors.New("fourauth: token issuer is required")
	}

	if !o.enableLocal && !o.enableGoogle {
		return errors.New("fourauth: at least one auth method must be enabled (local and/or google)")
	}

	if o.enableLocal && o.localProvider == nil {
		return errors.New("fourauth: local auth is enabled but local provider is not configured")
	}

	if o.enableGoogle && o.googleProvider == nil && o.googleCfg == nil {
		return errors.New("fourauth: google auth is enabled but no google config or provider was supplied")
	}

	if o.transport != nil && o.transport.Kind() == core.TransportKindBearer && o.csrfManager != nil {
		return errors.New("fourauth: csrf manager is only valid with cookie transport")
	}

	if o.transport.Kind() == core.TransportKindCookie && o.csrfManager == nil {
		return errors.New("fourauth: csrf manager is required when using cookie transport")
	}

	return nil
}

func finalizeOptions(o *options) error {
	if o.transport == nil {
		o.transport = cookietransport.New(*o.cookieCfg)
	}

	if o.csrfManager == nil && o.transport.Kind() == core.TransportKindCookie {
		o.csrfManager = csrf.NewManager(*o.cookieCfg)
	}

	if o.enableLocal {
		if o.hasher == nil {
			o.hasher = localprovider.NewBcrypt()
		}
		if o.localProvider == nil {
			o.localProvider = localprovider.New(o.hasher)
		}
	}

	if o.enableGoogle {
		if o.googleState == nil {
			o.googleState = googleprovider.NewState()
		}
		if o.googleProvider == nil {
			if o.googleCfg == nil {
				return errors.New("fourauth: google config is required when google auth is enabled")
			}
			o.googleProvider = googleprovider.NewProvider(o.googleCfg, o.googleState)
		}
	}

	return validateOptions(o)
}
