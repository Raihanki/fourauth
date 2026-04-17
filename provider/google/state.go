package google

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/Raihanki/fourauth/core"
)

// StateStore manages OAuth state for CSRF protection.
type StateStore struct {
	CookieName string
	Path       string
	Domain     string
	Secure     bool
	SameSite   http.SameSite
	MaxAge     time.Duration
}

// NewState creates a StateStore with default settings.
func NewState() *StateStore {
	return &StateStore{
		CookieName: "oauth_state",
		Path:       "/",
		Secure:     true,
		SameSite:   http.SameSiteLaxMode,
		MaxAge:     10 * time.Minute,
	}
}

// Issue generates and sets a new state cookie, returns the state value.
func (s *StateStore) Issue(w http.ResponseWriter, r *http.Request) (string, error) {
	state, err := s.newState()
	if err != nil {
		return "", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     s.CookieName,
		Value:    state,
		Path:     s.Path,
		Domain:   s.Domain,
		HttpOnly: true,
		Secure:   s.Secure,
		SameSite: s.SameSite,
		MaxAge:   int(s.MaxAge.Seconds()),
	})

	return state, nil
}

// Verify validates the state parameter against the stored cookie.
func (s *StateStore) Verify(r *http.Request, state string) error {
	if state == "" {
		return core.ErrStateMissing
	}

	c, err := r.Cookie(s.CookieName)
	if err != nil {
		return core.ErrStateMissing
	}

	if c.Value == "" {
		return core.ErrStateMissing
	}

	if subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
		return core.ErrStateInvalid
	}

	return nil
}

// Clear removes the state cookie.
func (s *StateStore) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.CookieName,
		Value:    "",
		Path:     s.Path,
		Domain:   s.Domain,
		HttpOnly: true,
		Secure:   s.Secure,
		SameSite: s.SameSite,
		MaxAge:   -1,
	})
}

func (s *StateStore) newState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
