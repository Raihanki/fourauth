package core

type UserInput interface {
	GetEmail() string
	GetPasswordHash() *string
	GetProvider() string
	GetProviderID() *string
	GetName() string
	GetAvatarURL() *string
	GetRole() string
	IsEmailVerified() bool
}
