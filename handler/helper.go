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

	resp := map[string]any{
		"access_token": pair.AccessToken.Value,
		"token_type":   "Bearer",
		"expires_at":   pair.AccessToken.ExpiredAt,
	}
	if pair.RefreshToken.Value != "" {
		resp["refresh_token"] = pair.RefreshToken.Value
	}

	_ = json.NewEncoder(w).Encode(resp)
}
