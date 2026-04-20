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
	"github.com/Raihanki/fourauth/handler"
	handlerpkg "github.com/Raihanki/fourauth/handler"
	middlewarepkg "github.com/Raihanki/fourauth/middleware"
	"github.com/Raihanki/fourauth/service"
)

// Auth provides authentication functionality and handlers.
type Auth struct {
	service        *service.Service
	middleware     *middlewarepkg.AuthMiddleware
	csrf           *csrf.Manager
	googleHandler  *handlerpkg.GoogleHandler
	localHandler   *handlerpkg.LocalHandler
	refreshHandler *handler.RefreshHandler
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

	googleHandler := &handlerpkg.GoogleHandler{
		Service:   svc,
		State:     o.googleState,
		Transport: o.transport,
	}

	localHandler := &handlerpkg.LocalHandler{
		Service:   svc,
		Transport: o.transport,
	}

	refreshHandler := &handler.RefreshHandler{
		Service:   svc,
		Transport: o.transport,
	}

	return &Auth{
		service: svc,
		csrf:    o.csrfManager,
		middleware: &middlewarepkg.AuthMiddleware{
			Repo:      o.repo,
			Issuer:    o.issuer,
			Transport: o.transport,
		},
		googleHandler:  googleHandler,
		localHandler:   localHandler,
		refreshHandler: refreshHandler,
	}, nil
}

// RequireAuth returns a middleware that redirects unauthenticated users
// and allows authenticated users to proceed to the next handler.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return a.middleware.RequireAuth(next)
}
