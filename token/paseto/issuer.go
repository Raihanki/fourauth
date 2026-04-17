package paseto

import (
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/token"
)

// Issuer is a token.Issuer that uses PASETO V4 local encryption.
type Issuer struct {
	key    paseto.V4SymmetricKey
	parser paseto.Parser
}

var _ token.Issuer = (*Issuer)(nil)

// New creates a new PASETO Issuer with the given symmetric key.
// The key must be 32 bytes (256 bits).
func New(key []byte) (*Issuer, error) {
	k, err := paseto.V4SymmetricKeyFromBytes(key)
	if err != nil {
		return nil, err
	}

	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())

	return &Issuer{
		key:    k,
		parser: parser,
	}, nil
}

func (i *Issuer) IssueAccessToken(claims core.AccessClaims) (core.Token, error) {
	t := paseto.NewToken()
	t.SetSubject(claims.Subject)
	t.SetString("email", claims.Email)
	t.SetString("role", claims.Role)
	t.SetExpiration(claims.ExpiresAt)
	t.SetIssuedAt(time.Now())

	token := t.V4Encrypt(i.key, nil)
	return core.Token{Value: token, ExpiredAt: claims.ExpiresAt}, nil
}

func (i *Issuer) IssueRefreshToken(claims core.RefreshClaims) (core.Token, error) {
	t := paseto.NewToken()
	t.SetSubject(claims.Subject)
	t.SetString("tid", claims.TokenID)
	t.SetExpiration(claims.ExpiresAt)
	t.SetIssuedAt(time.Now())

	raw := t.V4Encrypt(i.key, nil)

	return core.Token{
		Value:     raw,
		ExpiredAt: claims.ExpiresAt,
	}, nil
}

func (i *Issuer) ParseAccessToken(raw string) (core.AccessClaims, error) {
	t, err := i.parser.ParseV4Local(i.key, raw, nil)
	if err != nil {
		return core.AccessClaims{}, core.ErrInvalidToken
	}

	subject, err := t.GetSubject()
	if err != nil {
		return core.AccessClaims{}, core.ErrInvalidToken
	}

	email, err := t.GetString("email")
	if err != nil {
		return core.AccessClaims{}, core.ErrInvalidToken
	}

	role, err := t.GetString("role")
	if err != nil {
		return core.AccessClaims{}, core.ErrInvalidToken
	}

	exp, err := t.GetExpiration()
	if err != nil {
		return core.AccessClaims{}, core.ErrInvalidToken
	}

	return core.AccessClaims{
		Subject:   subject,
		Email:     email,
		Role:      role,
		ExpiresAt: exp,
	}, nil
}

func (i *Issuer) ParseRefreshToken(raw string) (core.RefreshClaims, error) {
	t, err := i.parser.ParseV4Local(i.key, raw, nil)
	if err != nil {
		return core.RefreshClaims{}, core.ErrInvalidToken
	}

	subject, err := t.GetSubject()
	if err != nil {
		return core.RefreshClaims{}, core.ErrInvalidToken
	}

	tokenID, err := t.GetString("tid")
	if err != nil {
		return core.RefreshClaims{}, core.ErrInvalidToken
	}

	exp, err := t.GetExpiration()
	if err != nil {
		return core.RefreshClaims{}, core.ErrInvalidToken
	}

	return core.RefreshClaims{
		Subject:   subject,
		TokenID:   tokenID,
		ExpiresAt: exp,
	}, nil
}

func (i *Issuer) Kind() core.TokenKind {
	return core.TokenKindPaseto
}
