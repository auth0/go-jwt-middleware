# Code Style

## Options pattern
All constructors use pure functional options — no exported config struct passed by value:
```go
// Good
func New(opts ...Option) *JWTMiddleware { ... }
func WithTokenExtractor(e TokenExtractor) Option {
    return func(m *JWTMiddleware) { m.extractor = e }
}

// Bad — do not expose a config struct as a public API
func New(cfg Config) *JWTMiddleware { ... }
```

## Generics for type-safe claims
Use `GetClaims[T]` / `MustGetClaims[T]` with a custom claims struct:
```go
type MyClaims struct {
    validator.RegisteredClaims
    OrgID string `json:"org_id"`
}
claims, ok := jwtmiddleware.GetClaims[*MyClaims](r.Context())
```

## Logger interface
`core.Logger` is a minimal slog-compatible interface (`Info`, `Error` accepting `msg string, keysAndValues ...any`). Default is `slog.Default()`. Accept the interface, not `*slog.Logger` directly, so callers can inject.

## Package documentation
Every package has a `doc.go` with a single-line package comment:
```go
// Package jwks provides JWKS (JSON Web Key Set) fetching and caching.
package jwks
```

## Error handling
- Wrap external errors with `fmt.Errorf("context: %w", err)`
- Exported sentinel errors belong in `core/errors.go` — add new ones there
- Do not expose raw `lestrrat-go/jwx` error types in the public API

## Context keys
Use an unexported type alias to avoid key collisions:
```go
type contextKey int
const claimsKey contextKey = iota
```

## Naming
- Option constructors: `WithXxx(value T) Option`
- No abbreviations in exported names: `CachingProvider` not `CachProvider`
- Test helper functions: `mustGenerateToken(t *testing.T, ...) string` — prefix with `must` and accept `*testing.T`
