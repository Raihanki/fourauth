# 📦 fourauth

**fourauth** is a modular and extensible authentication library for Go.

It provides a flexible way to implement authentication with support for:

- Local authentication (email/password)
- Google OAuth2 login
- JWT (EdDSA) and PASETO tokens
- Cookie-based and Bearer token transport
- CSRF protection (for cookie mode)
- Middleware and ready-to-use HTTP handlers

fourauth is designed to be:

- **plug-and-play** for simple apps  
- **composable** for custom architectures  
- **framework-agnostic**

---

# ✨ Features

- 🔐 Local authentication (email/password)
- 🌐 Google OAuth2 integration
- 🎟️ JWT (EdDSA) and PASETO support
- 🍪 Cookie-based auth with CSRF protection
- 🔑 Bearer token auth for APIs
- 🔄 Access + refresh token flow
- 🧩 Pluggable providers and repositories
- 🛡️ Middleware for protected routes

---

# 🚧 Status
⚠️ fourauth is currently in early development (`v0.x`) and may introduce breaking changes before `v1.0.0`.

# 🚀 Installation

```bash
go get github.com/Raihanki/fourauth
```

# Quickstart
```go
auth, err := fourauth.New(
    fourauth.WithUserRepository(userRepo),
    fourauth.WithRefreshTokenRepository(refreshRepo),
    fourauth.WithIssuer(jwtIssuer),
    fourauth.WithCookieTransport(),
    fourauth.WithLocalAuth(),
)
if err != nil {
    panic(err)
}
```

# Core Concepts

| Layer          | Purpose                   |
| -------------- | ------------------------- |
| **Service**    | Core auth logic           |
| **Provider**   | Local / Google auth       |
| **Token**      | JWT / PASETO              |
| **Transport**  | Cookie / Bearer           |
| **Handler**    | HTTP endpoints (optional) |
| **Middleware** | Route protection          |

# Configuration
fourauth uses an options pattern for setup.
### Required Options
```go
fourauth.WithUserRepository(...)
fourauth.WithRefreshTokenRepository(...)
fourauth.WithIssuer(...)
```
### Authentication Methods
At least one must be enabled.
#### Local (email/password)
```go
fourauth.WithLocalAuth()
```
Custom hasher:
```go
fourauth.WithHasher(myHasher)
```
#### Google OAuth
```go
fourauth.WithGoogleAuth(fourauth.NewGoogleConfig(
    clientID,
    clientSecret,
    redirectURL,
))
```

### Transport Modes
#### Cookie (default)
```go
fourauth.WithCookieTransport()
```
- Uses cookies for tokens
- CSRF protection is automatically enabled

##### Insecure Cookies (Development Only)
For local development over HTTP (e.g. `localhost`), you can disable `Secure` and `HttpOnly` cookie flags:
```go
fourauth.WithInsecureCookies()
```
> ⚠️ **NOT recommended for production.** Only use this during local development.

#### Bearer (API mode)
```go
fourauth.WithBearerTransport()
```
- Uses Authorization: Bearer <token>
- No CSRF

### Token Configuration
```go
fourauth.WithTokenConfig(fourauth.NewTokenConfig(
    "my-app",
    time.Minute*15,
    time.Hour*24,
))
```

# Example: Cookie + Local Auth
```go
auth, _ := fourauth.New(
    fourauth.WithUserRepository(userRepo),
    fourauth.WithRefreshTokenRepository(refreshRepo),
    fourauth.WithIssuer(jwtIssuer),
    fourauth.WithCookieTransport(),
    fourauth.WithLocalAuth(),
)
```
# Example: Google OAuth
```go
auth, _ := fourauth.New(
    fourauth.WithUserRepository(userRepo),
    fourauth.WithRefreshTokenRepository(refreshRepo),
    fourauth.WithIssuer(jwtIssuer),
    fourauth.WithCookieTransport(),
    fourauth.WithGoogleAuth(fourauth.NewGoogleConfig(
        clientID,
        clientSecret,
        redirectURL,
    )),
)
```

# HTTP Handlers
fourauth provides ready-to-use handlers:
### Local Auth
```go
mux.HandleFunc("POST /auth/register", auth.LocalRegisterHandler())
mux.HandleFunc("POST /auth/login", auth.LocalLoginHandler())
```
### Google Auth
```go
mux.HandleFunc("GET /auth/google", auth.GoogleRedirectHandler())
mux.HandleFunc("GET /auth/google/callback", auth.GoogleCallbackHandler())
```
### Refresh Token
```go
mux.HandleFunc("POST /auth/refresh", auth.RefreshTokenHandler())
```
### Current User
```go
mux.HandleFunc("GET /me", auth.MeHandler())
```

# Middleware
Protect routes:
```go
mux.Handle("/protected", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("ok"))
})))
```

# CSRF (Cookie Mode Only)
```go
mux.HandleFunc("GET /csrf", auth.CSRFHandler())
mux.Handle("/api", auth.CSRFMiddleware()(yourHandler))
```

# Using Only the Service Layer
You are not required to use handlers.
```go
svc := auth.Service()
result, err := svc.LoginLocal(ctx, email, password)
```

# Repositories
You must implement:
```go
type UserRepository interface {
    GetByEmail(...)
    GetByProvider(...)
    Create(...)
}

type RefreshTokenRepository interface {
    Save(...)
    Find(...)
    Revoke(...)
}
```
fourauth does not enforce any database or ORM.

# Token Issuers
You can use:

- JWT (EdDSA)
- PASETO (v4.local)

Or implement your own:
```go
type Issuer interface {
    IssueAccessToken(...)
    ParseAccessToken(...)
}
```

# Validation Rules
fourauth enforces:

- At least one auth method must be enabled
- CSRF is required for cookie transport
- CSRF is forbidden for bearer transport
- Google auth requires config or provider
