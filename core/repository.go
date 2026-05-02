package core

import "context"

// UserRepository defines the interface for user data persistence.
// Implement this interface to provide your own user storage backend.
type UserRepository interface {
	// GetByID retrieves a user by their unique identifier.
	GetByID(ctx context.Context, id string) (User, error)
	// GetByEmail retrieves a user by their email address.
	GetByEmail(ctx context.Context, email string) (User, error)
	// GetByProvider retrieves a user by their external identity provider and provider ID.
	GetByProvider(ctx context.Context, provider string, providerID string) (User, error)
	// Create creates a new user in the repository.
	Create(ctx context.Context, input UserInput) (User, error)
	// Update updates an existing user in the repository.
	Update(ctx context.Context, user User) error
}

// RefreshTokenRepository defines the interface for refresh token persistence.
// Used to store and revoke refresh tokens for session management.
type RefreshTokenRepository interface {
	// Save stores a refresh token record.
	Save(ctx context.Context, token RefreshTokenRecord) error
	// Find retrieves a refresh token by its ID.
	Find(ctx context.Context, tokenID string) (RefreshTokenRecord, error)
	// Revoke marks a refresh token as revoked, preventing future use.
	Revoke(ctx context.Context, tokenID string) error
}
