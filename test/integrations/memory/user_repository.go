package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/Raihanki/fourauth/core"
	"github.com/Raihanki/fourauth/model"
)

type memUserRepo struct {
	mu         sync.Mutex
	nextID     int
	byID       map[string]*model.BaseUser
	byEmail    map[string]*model.BaseUser
	byProvider map[string]*model.BaseUser
}

func NewMemUserRepo() *memUserRepo {
	return &memUserRepo{
		byID:       map[string]*model.BaseUser{},
		byEmail:    map[string]*model.BaseUser{},
		byProvider: map[string]*model.BaseUser{},
	}
}

func providerKey(provider, providerID string) string {
	return provider + ":" + providerID
}

func (r *memUserRepo) GetByID(_ context.Context, id string) (core.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	u, ok := r.byID[id]
	if !ok {
		return nil, errNotFound
	}
	return u, nil
}

func (r *memUserRepo) GetByEmail(_ context.Context, email string) (core.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	u, ok := r.byEmail[email]
	if !ok {
		return nil, errNotFound
	}
	return u, nil
}

func (r *memUserRepo) GetByProvider(_ context.Context, provider string, providerID string) (core.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	u, ok := r.byProvider[providerKey(provider, providerID)]
	if !ok {
		return nil, errNotFound
	}
	return u, nil
}

func (r *memUserRepo) Create(_ context.Context, in core.UserInput) (core.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.nextID++
	id := fmt.Sprintf("user-%d", r.nextID)

	var passwordHash *string
	if in.GetPasswordHash() != nil {
		v := *in.GetPasswordHash()
		passwordHash = &v
	}

	var providerID *string
	if in.GetProviderID() != nil {
		v := *in.GetProviderID()
		providerID = &v
	}

	u := &model.BaseUser{
		ID:            id,
		Email:         in.GetEmail(),
		PasswordHash:  passwordHash,
		Provider:      in.GetProvider(),
		ProviderID:    providerID,
		Role:          in.GetRole(),
		EmailVerified: in.IsEmailVerified(),
	}

	r.byID[id] = u
	r.byEmail[in.GetEmail()] = u
	if providerID != nil {
		r.byProvider[providerKey(in.GetProvider(), *providerID)] = u
	}

	return u, nil
}

func (r *memUserRepo) Update(_ context.Context, _ core.User) error {
	return nil
}
