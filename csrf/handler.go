package csrf

import "net/http"

// Handler returns an HTTP handler that issues a new CSRF token.
// The token is set as a cookie, and the token value is returned in the response.
func Handler(m *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := m.Issue(w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
