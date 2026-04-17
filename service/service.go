// Package service provides the core authentication business logic.
//
// This package handles user registration, login, token refresh, and OAuth flows.
// It is used by the HTTP handlers but can also be used directly for custom integrations.
package service

import (
	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/csrf"
	"github.com/Raihanki/fourauth/provider"
	"github.com/Raihanki/fourauth/provider/google"
	"github.com/Raihanki/fourauth/token"
	"github.com/Raihanki/fourauth/transport"
)

// Service handles authentication operations.
type Service struct {
	tokenCfg    *core.TokenConfig
	repo        core.UserRepository
	refreshRepo core.RefreshTokenRepository
	issuer      token.Issuer
	transport   transport.Transport
	csrf        *csrf.Manager
	local       provider.PasswordProvider
	google      provider.ExternalProvider
	googleState *google.StateStore
}

// New creates a new Service with the given configuration.
func New(
	tokenCfg *core.TokenConfig,
	repo core.UserRepository,
	refreshRepo core.RefreshTokenRepository,
	issuer token.Issuer,
	transport transport.Transport,
	csrf *csrf.Manager,
	localProv provider.PasswordProvider,
	googleProv provider.ExternalProvider,
) *Service {
	return &Service{
		tokenCfg:    tokenCfg,
		repo:        repo,
		refreshRepo: refreshRepo,
		issuer:      issuer,
		transport:   transport,
		csrf:        csrf,
		local:       localProv,
		google:      googleProv,
	}
}
