package handler

import (
	"net/http"

	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/provider/google"
	"github.com/Raihanki/fourauth/service"
	transportpkg "github.com/Raihanki/fourauth/transport"
)

// GoogleHandler handles Google OAuth2 authentication endpoints.
type GoogleHandler struct {
	// Service is the authentication service.
	Service *service.Service
	// State is the OAuth state store.
	State *google.StateStore
	// Transport is the token transport.
	Transport transportpkg.Transport
}

// Redirect redirects the user to Google for authentication.
func (h GoogleHandler) Redirect(w http.ResponseWriter, r *http.Request) {
	state, err := h.State.Issue(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	url, _, err := h.Service.GoogleAuthURL(state)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Callback handles the OAuth callback from Google.
// Exchanges the authorization code for tokens and writes them to the response.
func (h GoogleHandler) Callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	if err := h.State.Verify(r, state); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	h.State.Clear(w)

	result, err := h.Service.LoginGoogleCallback(r.Context(), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	switch h.Transport.Kind() {
	case core.TransportKindCookie:
		if err := h.Transport.WriteTokens(w, result.Tokens); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		return

	case core.TransportKindBearer:
		WriteBearerTokenResponse(w, result.Tokens)
		return

	default:
		http.Error(w, "unsupported transport", http.StatusInternalServerError)
		return
	}
}
