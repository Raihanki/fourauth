package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequireRole(t *testing.T) {
	t.Run("forbidden when user missing from context", func(t *testing.T) {
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler := RequireRole("admin")(next)

		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.False(t, nextCalled)
		assert.Contains(t, rr.Body.String(), "forbidden")
	})

	t.Run("forbidden when user role does not match", func(t *testing.T) {
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler := RequireRole("admin")(next)

		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		req = req.WithContext(WithUser(req.Context(), testUser{
			id:    "user-1",
			email: "user@example.com",
			role:  "user",
		}))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.False(t, nextCalled)
		assert.Contains(t, rr.Body.String(), "forbidden")
	})

	t.Run("calls next when user role matches", func(t *testing.T) {
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true

			user, ok := UserFromContext(r.Context())
			require.True(t, ok)
			assert.Equal(t, "admin", user.GetRole())

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})

		handler := RequireRole("admin")(next)

		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		req = req.WithContext(WithUser(req.Context(), testUser{
			id:    "user-1",
			email: "admin@example.com",
			role:  "admin",
		}))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.True(t, nextCalled)
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "ok", rr.Body.String())
	})
}
