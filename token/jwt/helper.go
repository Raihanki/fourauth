package jwt

import "crypto/ed25519"

// GenerateKeyPair generates a new Ed25519 key pair for JWT signing.
// The public key is used for verification, the private key for signing.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	return pub, priv, err
}
