package transport

import (
	"net/http"

	"github.com/Raihanki/fourauth/core"
)

type Transport interface {
	WriteTokens(w http.ResponseWriter, pair core.TokenPair) error
	ReadAccessToken(r *http.Request) (string, error)
	ReadRefreshToken(r *http.Request) (string, error)
	Clear(w http.ResponseWriter) error
	Kind() core.TransportKind
}
