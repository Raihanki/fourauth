package bearer

import (
	"net/http"
	"strings"

	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/transport"
)

type Transport struct{}

var _ transport.Transport = (*Transport)(nil)

func New() *Transport { return &Transport{} }

func (t *Transport) WriteTokens(w http.ResponseWriter, pair core.TokenPair) error {
	return core.ErrUnsupportedWriteTokens
}

func (t *Transport) ReadAccessToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", core.ErrMissingAuthorizationHeader
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", core.ErrMissingAuthorizationHeader
	}
	return strings.TrimPrefix(h, prefix), nil
}

func (t *Transport) ReadRefreshToken(r *http.Request) (string, error) {
	return "", core.ErrUnsupportedRefreshRead
}

func (t *Transport) Clear(w http.ResponseWriter) error {
	return core.ErrUnsupportedClear
}

func (t *Transport) Kind() core.TransportKind {
	return core.TransportKindBearer
}
