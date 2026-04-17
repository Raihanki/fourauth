package handler

import (
	"encoding/json"
	"net/http"

	"github.com/Raihanki/fourauth/middleware"
)

// Me returns the authenticated user's information.
// Expects the user to be in the request context (via RequireAuth middleware).
func Me(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":    user.GetID(),
		"email": user.GetEmail(),
		"role":  user.GetRole(),
	})
}
