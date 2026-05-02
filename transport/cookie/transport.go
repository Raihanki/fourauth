package cookie

import (
	"net/http"
	"time"

	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/transport"
)

type Transport struct {
	cfg core.CookieConfig
}

var _ transport.Transport = (*Transport)(nil)

func New(cfg core.CookieConfig) *Transport {
	return &Transport{cfg: cfg}
}

func (t *Transport) WriteTokens(w http.ResponseWriter, pair core.TokenPair) error {
	http.SetCookie(w, &http.Cookie{
		Name:     t.cfg.AccessCookieName,
		Value:    pair.AccessToken.Value,
		Path:     t.cfg.Path,
		Domain:   t.cfg.Domain,
		HttpOnly: t.cfg.HTTPOnly,
		Secure:   t.cfg.Secure,
		SameSite: t.cfg.SameSite,
		Expires:  pair.AccessToken.ExpiredAt,
		MaxAge:   maxAgeFrom(pair.AccessToken.ExpiredAt),
	})

	if pair.RefreshToken.Value != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     t.cfg.RefreshCookieName,
			Value:    pair.RefreshToken.Value,
			Path:     t.cfg.Path,
			Domain:   t.cfg.Domain,
			HttpOnly: t.cfg.HTTPOnly,
			Secure:   t.cfg.Secure,
			SameSite: t.cfg.SameSite,
			Expires:  pair.RefreshToken.ExpiredAt,
			MaxAge:   maxAgeFrom(pair.RefreshToken.ExpiredAt),
		})
	}

	return nil
}

func (t *Transport) ReadAccessToken(r *http.Request) (string, error) {
	c, err := r.Cookie(t.cfg.AccessCookieName)
	if err != nil {
		return "", err
	}
	return c.Value, nil
}

func (t *Transport) ReadRefreshToken(r *http.Request) (string, error) {
	c, err := r.Cookie(t.cfg.RefreshCookieName)
	if err != nil {
		return "", err
	}
	return c.Value, nil
}

func (t *Transport) Clear(w http.ResponseWriter) error {
	for _, name := range []string{t.cfg.AccessCookieName, t.cfg.RefreshCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     t.cfg.Path,
			Domain:   t.cfg.Domain,
			MaxAge:   -1,
			HttpOnly: t.cfg.HTTPOnly,
			Secure:   t.cfg.Secure,
			SameSite: t.cfg.SameSite,
		})
	}
	return nil
}

func (t *Transport) Kind() core.TransportKind {
	return core.TransportKindCookie
}

func maxAgeFrom(exp time.Time) int {
	return max(0, int(time.Until(exp).Seconds()))
}
