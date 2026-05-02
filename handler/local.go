package handler

import (
	"encoding/json"
	"net/http"

	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/service"
	transportpkg "github.com/Raihanki/fourauth/transport"
)

// LocalHandler handles local email/password authentication endpoints.
type LocalHandler struct {
	// Service is the authentication service.
	Service *service.Service
	// Transport is the token transport.
	Transport transportpkg.Transport
}

// registerRequest is the JSON request body for registration.
type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
	Role     string `json:"role"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Register handles user registration.
func (h LocalHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := h.Service.Register(r.Context(), service.RegisterInput{
		Email:    req.Email,
		Password: req.Password,
		Name:     req.Name,
		Role:     req.Role,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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

// Login handles user login.
// Expects JSON body: {"email", "password"}
func (h LocalHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := h.Service.LoginLocal(r.Context(), req.Email, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	_ = h.Transport.WriteTokens(w, result.Tokens)
	w.WriteHeader(http.StatusOK)
}
