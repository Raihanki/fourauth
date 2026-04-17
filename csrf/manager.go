package csrf

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/Raihanki/fourauth/core"
)

// Manager manages CSRF token issuance and validation.
type Manager struct {
	cfg core.CookieConfig
}

// NewManager creates a new CSRF Manager with the given cookie configuration.
func NewManager(cfg core.CookieConfig) *Manager {
	return &Manager{cfg: cfg}
}

func generateCSRFTokenValue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	return token, nil
}

// Issue generates a new CSRF token and sets it as a cookie.
func (m *Manager) Issue(w http.ResponseWriter) (string, error) {
	token, err := generateCSRFTokenValue()
	if err != nil {
		return "", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     m.cfg.CSRFCookieName,
		Value:    token,
		Path:     m.cfg.Path,
		Domain:   m.cfg.Domain,
		HttpOnly: false,
		Secure:   m.cfg.Secure,
		SameSite: m.cfg.SameSite,
	})
	return token, nil
}

// Validate checks if the CSRF token in the cookie matches the request header.
func (m *Manager) Validate(r *http.Request) error {
	cookie, err := r.Cookie(m.cfg.CSRFCookieName)
	if err != nil {
		return core.ErrCSRFTokenMissing
	}
	header := r.Header.Get(m.cfg.CSRFHeaderName)
	if header == "" {
		return core.ErrCSRFTokenMissing
	}
	if cookie.Value != header {
		return core.ErrCSRFTokenInvalid
	}
	return nil
}
