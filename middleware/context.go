package middleware

import (
	"context"

	"github.com/Raihanki/fourauth/core"
)

type contextKey string

// Defines the key for the user in the context.
const userContextKey contextKey = "fourauth.user"

// WithUser adds a user to the context.
func WithUser(ctx context.Context, user core.User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

// UserFromContext retrieves a user from the context.
func UserFromContext(ctx context.Context) (core.User, bool) {
	v := ctx.Value(userContextKey)
	if v == nil {
		return nil, false
	}
	u, ok := v.(core.User)
	return u, ok
}
