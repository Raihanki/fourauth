package core

// User defines the interface for authenticated user data.
// Implement this interface to provide your own user model.
type User interface {
	// GetID returns the user's unique identifier.
	GetID() string
	// GetEmail returns the user's email address.
	GetEmail() string
	// GetPasswordHash returns the hashed password for local authentication.
	GetPasswordHash() *string
	// GetProvider returns the primary authentication provider.
	GetProvider() string
	// GetProviderID returns the external provider ID for OAuth logins.
	GetProviderID() *string
	// GetRole returns the user's role (e.g., "admin", "user").
	GetRole() string
	// IsEmailVerified returns whether the email has been verified.
	IsEmailVerified() bool
}
