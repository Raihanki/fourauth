package model

type BaseUserInput struct {
	Email         string
	PasswordHash  *string
	Provider      string
	ProviderID    *string
	Name          string
	AvatarURL     *string
	Role          string
	EmailVerified bool
}

func (u BaseUserInput) GetEmail() string         { return u.Email }
func (u BaseUserInput) GetPasswordHash() *string { return u.PasswordHash }
func (u BaseUserInput) GetProvider() string      { return u.Provider }
func (u BaseUserInput) GetProviderID() *string   { return u.ProviderID }
func (u BaseUserInput) GetName() string          { return u.Name }
func (u BaseUserInput) GetAvatarURL() *string    { return u.AvatarURL }
func (u BaseUserInput) GetRole() string          { return u.Role }
func (u BaseUserInput) IsEmailVerified() bool    { return u.EmailVerified }
