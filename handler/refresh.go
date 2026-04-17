package handler

import (
	"net/http"

	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/service"
	transportpkg "github.com/Raihanki/fourauth/transport"
)

// RefreshHandler handles token refresh requests.
type RefreshHandler struct {
	// Service is the authentication service.
	Service *service.Service
	// Transport is the token transport.
	Transport transportpkg.Transport
}

// Handle exchanges a refresh token for new access/refresh tokens.
func (h RefreshHandler) Handle(w http.ResponseWriter, r *http.Request) {
	raw, err := h.Transport.ReadRefreshToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	result, err := h.Service.Refresh(r.Context(), raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	switch h.Transport.Kind() {
	case core.TransportKindCookie:
		if err := h.Transport.WriteTokens(w, result); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		return

	case core.TransportKindBearer:
		WriteBearerTokenResponse(w, result)
		return

	default:
		http.Error(w, "unsupported transport", http.StatusInternalServerError)
		return
	}
}
