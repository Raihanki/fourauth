// Package fourauth provides authentication functionality for Go applications.
//
// This package supports multiple authentication methods including local (email/password)
// and Google OAuth2. It provides token-based authentication with refresh tokens,
// CSRF protection, and middleware for protecting routes.
//
// # Quick Start
//
//	auth, err := fourauth.New(
//	    fourauth.WithUserRepository(myUserRepo),
//	    fourauth.WithRefreshTokenRepository(myRefreshTokenRepo),
//	    fourauth.WithIssuer(myIssuer),
//	    fourauth.WithCookieTransport(),
//	    fourauth.WithLocalAuth(),
//	    fourauth.WithHasher(local.NewBcrypt()),
//	)
//
// For more configuration options, see the Option functions like WithGoogleAuth,
// WithBearerTransport, and WithCSRFManager.
package fourauth

import (
	"net/http"

	"github.com/Raihanki/fourauth/csrf"
	handlerpkg "github.com/Raihanki/fourauth/handler"
	middlewarepkg "github.com/Raihanki/fourauth/middleware"
	"github.com/Raihanki/fourauth/service"
)

// Auth provides authentication functionality and handlers.
type Auth struct {
	service    *service.Service
	middleware *middlewarepkg.AuthMiddleware
	csrf       *csrf.Manager
}

// New creates a new Auth instance with the given options.
// It returns an error if required options are missing or invalid.
func New(opts ...Option) (*Auth, error) {
	o := defaultOptions()

	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}

	if err := finalizeOptions(o); err != nil {
		return nil, err
	}

	svc := service.New(
		&o.tokenCfg,
		o.repo,
		o.refreshRepo,
		o.issuer,
		o.transport,
		o.csrfManager,
		o.localProvider,
		o.googleProvider,
	)

	return &Auth{
		service: svc,
		csrf:    o.csrfManager,
		middleware: &middlewarepkg.AuthMiddleware{
			Repo:      o.repo,
			Issuer:    o.issuer,
			Transport: o.transport,
		},
	}, nil
}

// RequireAuth returns a middleware that redirects unauthenticated users
// and allows authenticated users to proceed to the next handler.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return a.middleware.RequireAuth(next)
}

// CSRFHandler returns a handler that generates and sets CSRF tokens.
// Returns 404 if CSRF is not enabled.
func (a *Auth) CSRFHandler() http.HandlerFunc {
	if a.csrf == nil {
		return func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "csrf is not enabled", http.StatusNotFound)
		}
	}
	return csrf.Handler(a.csrf)
}

// CSRFMiddleware returns middleware that validates CSRF tokens on stateful requests.
// Returns a no-op middleware if CSRF is not enabled.
func (a *Auth) CSRFMiddleware() func(http.Handler) http.Handler {
	if a.csrf == nil {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	return csrf.Protect(a.csrf)
}

// MeHandler returns a handler that returns the currently authenticated user.
// Returns user data as JSON with fields: id, email, name, role, avatar_url, provider.
func (a *Auth) MeHandler() http.HandlerFunc {
	return handlerpkg.Me
}
