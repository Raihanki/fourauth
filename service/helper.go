package service

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/Raihanki/fourauth/core"
)

func (s *Service) issueTokenPair(user core.User) (core.TokenPair, error) {
	access, err := s.issuer.IssueAccessToken(core.AccessClaims{
		Subject:   user.GetID(),
		Email:     user.GetEmail(),
		Role:      user.GetRole(),
		ExpiresAt: time.Now().Add(s.tokenCfg.AccessTokenTTL),
	})
	if err != nil {
		return core.TokenPair{}, err
	}

	refreshID, err := randomTokenID()
	if err != nil {
		return core.TokenPair{}, err
	}

	refresh, err := s.issuer.IssueRefreshToken(core.RefreshClaims{
		Subject:   user.GetID(),
		TokenID:   refreshID,
		ExpiresAt: time.Now().Add(s.tokenCfg.RefreshTokenTTL),
	})
	if err != nil {
		return core.TokenPair{}, err
	}

	return core.TokenPair{AccessToken: access, RefreshToken: refresh}, nil
}

func randomTokenID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
