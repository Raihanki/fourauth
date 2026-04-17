package jwt

import (
	"crypto/ed25519"
	"time"

	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/token"
	"github.com/golang-jwt/jwt/v5"
)

// Config holds Ed25519 key pair for JWT signing.
type Config struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// Issuer is a token.Issuer that uses JWT with Ed25519 signatures.
type Issuer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

var _ token.Issuer = (*Issuer)(nil)

// New creates a new JWT Issuer with the given Ed25519 key pair.
func New(cfg Config) *Issuer {
	return &Issuer{
		privateKey: cfg.PrivateKey,
		publicKey:  cfg.PublicKey,
	}
}

func (i *Issuer) IssueAccessToken(claims core.AccessClaims) (core.Token, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"sub":   claims.Subject,
		"email": claims.Email,
		"role":  claims.Role,
		"exp":   claims.ExpiresAt.Unix(),
		"iat":   time.Now().Unix(),
	})

	token, err := t.SignedString(i.privateKey)
	if err != nil {
		return core.Token{}, err
	}

	return core.Token{Value: token, ExpiredAt: claims.ExpiresAt}, nil
}

func (i *Issuer) IssueRefreshToken(claims core.RefreshClaims) (core.Token, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"sub": claims.Subject,
		"tid": claims.TokenID,
		"exp": claims.ExpiresAt.Unix(),
		"iat": time.Now().Unix(),
	})

	token, err := t.SignedString(i.privateKey)
	if err != nil {
		return core.Token{}, err
	}

	return core.Token{Value: token, ExpiredAt: claims.ExpiresAt}, nil
}

func (i *Issuer) ParseAccessToken(raw string) (core.AccessClaims, error) {
	token, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodEdDSA {
			return nil, core.ErrInvalidToken
		}
		return i.publicKey, nil
	})
	if err != nil {
		return core.AccessClaims{}, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return core.AccessClaims{}, core.ErrInvalidToken
	}

	return core.AccessClaims{
		Subject: claims["sub"].(string),
		Email:   claims["email"].(string),
		Role:    claims["role"].(string),
	}, nil
}

func (i *Issuer) ParseRefreshToken(raw string) (core.RefreshClaims, error) {
	token, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodEdDSA {
			return nil, core.ErrInvalidToken
		}
		return i.publicKey, nil
	})
	if err != nil {
		return core.RefreshClaims{}, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return core.RefreshClaims{}, core.ErrInvalidToken
	}

	return core.RefreshClaims{
		Subject: claims["sub"].(string),
		TokenID: claims["tid"].(string),
	}, nil
}

func (i *Issuer) Kind() core.TokenKind {
	return core.TokenKindJWT
}
