package local

import "golang.org/x/crypto/bcrypt"

// Bcrypt is a PasswordProvider that uses bcrypt for hashing.
type Bcrypt struct{}

// NewBcrypt creates a new Bcrypt hasher.
func NewBcrypt() *Bcrypt {
	return &Bcrypt{}
}

// Hash implements PasswordProvider.
func (b *Bcrypt) Hash(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashed), nil
}

// Compare implements PasswordProvider.
func (b *Bcrypt) Compare(hash string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
