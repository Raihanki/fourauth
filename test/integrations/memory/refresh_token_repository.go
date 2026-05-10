package memory

import (
	"context"
	"sync"
	"time"

	"github.com/Raihanki/fourauth/core"
)

type memRefreshRepo struct {
	mu    sync.Mutex
	byID  map[string]core.RefreshTokenRecord
}

func NewMemRefreshRepo() *memRefreshRepo {
	return &memRefreshRepo{
		byID: map[string]core.RefreshTokenRecord{},
	}
}

func (r *memRefreshRepo) Save(_ context.Context, token core.RefreshTokenRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.byID[token.TokenID] = token
	return nil
}

func (r *memRefreshRepo) Find(_ context.Context, tokenID string) (core.RefreshTokenRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec, ok := r.byID[tokenID]
	if !ok {
		return core.RefreshTokenRecord{}, errNotFound
	}
	return rec, nil
}

func (r *memRefreshRepo) Revoke(_ context.Context, tokenID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec, ok := r.byID[tokenID]
	if !ok {
		return errNotFound
	}
	now := time.Now()
	rec.RevokedAt = &now
	r.byID[tokenID] = rec
	return nil
}
