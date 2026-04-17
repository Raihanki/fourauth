package model

import "time"

type BaseUser struct {
	ID            string
	Email         string
	PasswordHash  *string
	Provider      string
	ProviderID    *string
	Name          string
	AvatarURL     *string
	Role          string
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (u BaseUser) GetID() string            { return u.ID }
func (u BaseUser) GetEmail() string         { return u.Email }
func (u BaseUser) GetPasswordHash() *string { return u.PasswordHash }
func (u BaseUser) GetProvider() string      { return u.Provider }
func (u BaseUser) GetProviderID() *string   { return u.ProviderID }
func (u BaseUser) GetRole() string          { return u.Role }
func (u BaseUser) IsEmailVerified() bool    { return u.EmailVerified }
