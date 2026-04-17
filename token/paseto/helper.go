package paseto

import (
	"crypto/rand"
	"encoding/base64"
)

// GenerateSymmetricKey generates a new 256-bit symmetric key for PASETO encryption.
func GenerateSymmetricKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateSymmetricKeyString generates a symmetric key as a base64url-encoded string.
func GenerateSymmetricKeyString() (string, error) {
	key, err := GenerateSymmetricKey()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(key), nil
}

// ParseSymmetricKey decodes a base64url-encoded symmetric key.
func ParseSymmetricKey(encoded string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(encoded)
}
