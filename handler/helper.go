package handler

import (
	"encoding/json"
	"net/http"

	"github.com/Raihanki/fourauth/core"
)

// WriteBearerTokenResponse writes a token pair as a JSON Bearer token response.
func WriteBearerTokenResponse(w http.ResponseWriter, pair core.TokenPair) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  pair.AccessToken.Value,
		"refresh_token": pair.RefreshToken.Value,
		"token_type":    "Bearer",
		"expires_at":    pair.AccessToken.ExpiredAt,
	})
}
