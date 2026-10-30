# Code Style

## Options pattern
All constructors use pure functional options — no exported config struct passed by value:
```go
// Good
func New(opts ...Option) (*JWTMiddleware, error) { ... }
func WithTokenExtractor(e TokenExtractor) Option {
    return func(m *JWTMiddleware) { m.extractor = e }
}

// Bad — do not expose a config struct as a public API
func New(cfg Config) (*JWTMiddleware, error) { ... }
```

## Generics for type-safe claims
The middleware stores `*validator.ValidatedClaims` in the request context. Retrieve it with `GetClaims[T]` (returns `(T, error)`) or `MustGetClaims[T]`, and register custom claims with `validator.WithCustomClaims`:
```go
type MyClaims struct {
    OrgID string `json:"org_id"`
}

func (c *MyClaims) Validate(ctx context.Context) error { return nil }

v, err := validator.New(
    // ...issuer, audience, algorithm, keyFunc options...
    validator.WithCustomClaims(func() *MyClaims { return &MyClaims{} }),
)

claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
if err != nil {
    // handle missing claims
}
myClaims := claims.CustomClaims.(*MyClaims)
```

## Logger interface
`core.Logger` is a minimal slog-compatible interface (`Debug`, `Info`, `Warn`, `Error`, each accepting `msg string, args ...any`). Default is `slog.Default()`. Accept the interface, not `*slog.Logger` directly, so callers can inject.

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
