package csrf

import "net/http"

// Protect returns middleware that validates CSRF tokens on stateful requests.
// GET, HEAD, and OPTIONS requests are allowed without CSRF validation.
// All other requests must include a valid CSRF token in the header.
func Protect(m *Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}

			if err := m.Validate(r); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
