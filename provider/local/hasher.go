package local

// Hasher defines the interface for password hashing implementations.
type Hasher interface {
	// Hash generates a hash of the password.
	Hash(password string) (string, error)
	// Compare compares a password against a hash.
	Compare(hash string, password string) error
}
