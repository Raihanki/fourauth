package handler

import (
	"net/http"

	"github.com/Raihanki/fourauth/core"
	transportpkg "github.com/Raihanki/fourauth/transport"
)

// LogoutHandler handles user logout by clearing tokens.
type LogoutHandler struct {
	// Transport is the token transport.
	Transport transportpkg.Transport
}

// Handle clears authentication tokens and logs out the user.
func (h LogoutHandler) Handle(w http.ResponseWriter, r *http.Request) {
	switch h.Transport.Kind() {
	case core.TransportKindCookie:
		if err := h.Transport.Clear(w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		return

	default:
		http.Error(w, "unsupported transport", http.StatusInternalServerError)
		return
	}
}
