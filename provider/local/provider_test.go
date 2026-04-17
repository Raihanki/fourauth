package local

import (
	"testing"

	"github.com/Raihanki/fourauth/core"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	p := New(NewTestBcrypt(t))
	assert.NotNil(t, p)
	assert.Equal(t, &Provider{Hasher: &Bcrypt{}}, p)
}

func TestProvider_Name(t *testing.T) {
	p := New(NewTestBcrypt(t))
	name := p.Name()
	assert.Equal(t, core.ProviderLocal, name)
}
