package fourauth

import (
	"net/http"

	"github.com/Raihanki/fourauth/csrf"
	handlerpkg "github.com/Raihanki/fourauth/handler"
)

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

func (a *Auth) GoogleRedirectHandler() http.HandlerFunc {
	return a.googleHandler.Redirect
}

func (a *Auth) GoogleCallbackHandler() http.HandlerFunc {
	return a.googleHandler.Callback
}

func (a *Auth) localRegisterHandler() http.HandlerFunc {
	return a.localHandler.Register
}

func (a *Auth) localLoginHandler() http.HandlerFunc {
	return a.localHandler.Login
}

func (a *Auth) refreshTokenHandler() http.HandlerFunc {
	return a.refreshHandler.Handle
}
