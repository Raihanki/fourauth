package local

import (
	"github.com/Raihanki/fourauth/core"
)

// Provider is a PasswordProvider for local email/password authentication.
type Provider struct {
	Hasher Hasher
}

// New creates a new local Provider with the given hasher.
func New(hasher Hasher) *Provider {
	return &Provider{Hasher: hasher}
}

func (p *Provider) Name() core.ProviderName {
	return core.ProviderLocal
}

func (p *Provider) Hash(password string) (string, error) {
	return p.Hasher.Hash(password)
}

func (p *Provider) Compare(hash string, password string) error {
	return p.Hasher.Compare(hash, password)
}
