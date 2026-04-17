package local

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func NewTestBcrypt(t *testing.T) *Bcrypt {
	b := NewBcrypt()
	assert.NotNil(t, b)
	assert.Equal(t, &Bcrypt{}, b)

	return b
}

func TestBcrypt_Hash(t *testing.T) {
	b := NewTestBcrypt(t)
	hash, err := b.Hash("secret")
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)
}

func TestBcrypt_Compare(t *testing.T) {
	b := NewTestBcrypt(t)
	hash, err := b.Hash("secret")
	assert.NoError(t, err)

	err = b.Compare(hash, "secret")
	assert.NoError(t, err)
}

func TestBcrypt_CompareError(t *testing.T) {
	b := NewTestBcrypt(t)
	hash, err := b.Hash("secret")
	assert.NoError(t, err)

	err = b.Compare(hash, "not secret")
	assert.Error(t, err)
}
