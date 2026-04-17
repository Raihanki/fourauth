package middleware

import (
	"net/http"

	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/token"
	transportpkg "github.com/Raihanki/fourauth/transport"
)

// AuthMiddleware handles request authentication.
type AuthMiddleware struct {
	// Repo is the user repository for loading users.
	Repo core.UserRepository
	// Issuer is the token issuer for parsing tokens.
	Issuer token.Issuer
	// Transport is the token transport for reading tokens from requests.
	Transport transportpkg.Transport
}

// RequireAuth returns middleware that enforces authentication.
// Adds authenticated user to request context on success.
func (m AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := m.Transport.ReadAccessToken(r)
		if err != nil {
			http.Error(w, core.ErrUnauthorized.Error(), http.StatusUnauthorized)
			return
		}

		claims, err := m.Issuer.ParseAccessToken(raw)
		if err != nil {
			http.Error(w, core.ErrUnauthorized.Error(), http.StatusUnauthorized)
			return
		}

		user, err := m.Repo.GetByID(r.Context(), claims.Subject)
		if err != nil {
			http.Error(w, core.ErrUnauthorized.Error(), http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), user)))
	})
}
