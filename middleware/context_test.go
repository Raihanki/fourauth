package middleware

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithUserAndUserFromContext(t *testing.T) {
	wantUser := testUser{
		id:            "user-1",
		email:         "user@example.com",
		role:          "admin",
		emailVerified: true,
	}

	ctx := WithUser(context.Background(), wantUser)

	gotUser, ok := UserFromContext(ctx)
	require.True(t, ok)
	require.NotNil(t, gotUser)

	assert.Equal(t, wantUser.GetID(), gotUser.GetID())
	assert.Equal(t, wantUser.GetEmail(), gotUser.GetEmail())
	assert.Equal(t, wantUser.GetRole(), gotUser.GetRole())
	assert.Equal(t, wantUser.IsEmailVerified(), gotUser.IsEmailVerified())
}

func TestUserFromContext_Missing(t *testing.T) {
	gotUser, ok := UserFromContext(context.Background())

	assert.False(t, ok)
	assert.Nil(t, gotUser)
}

func TestUserFromContext_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), userContextKey, "not-a-user")

	gotUser, ok := UserFromContext(ctx)

	assert.False(t, ok)
	assert.Nil(t, gotUser)
}
