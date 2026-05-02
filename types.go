package fourauth

import "github.com/Raihanki/fourauth/core"

type User = core.User

type UserRepository = core.UserRepository
type RefreshTokenRepository = core.RefreshTokenRepository

type ProviderName = core.ProviderName
type TokenKind = core.TokenKind
type TransportKind = core.TransportKind

type Token = core.Token
type TokenPair = core.TokenPair
type AuthResult = core.AuthResult
type ExternalIdentity = core.ExternalIdentity
type UserInput = core.UserInput
type RefreshTokenRecord = core.RefreshTokenRecord

type TokenConfig = core.TokenConfig
type CookieConfig = core.CookieConfig
type BearerConfig = core.BearerConfig
type GoogleConfig = core.GoogleConfig

const (
	ProviderLocal  = core.ProviderLocal
	ProviderGoogle = core.ProviderGoogle

	TokenKindJWT    = core.TokenKindJWT
	TokenKindPaseto = core.TokenKindPaseto

	TransportKindCookie = core.TransportKindCookie
	TransportKindBearer = core.TransportKindBearer
)
