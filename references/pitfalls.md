# Common Pitfalls

1. **Algorithm inference for keys without `alg`**: `lestrrat-go/jwx v3` requires explicit algorithm specification when a JWKS key omits the optional `alg` member. The validator passes `jws.WithInferAlgorithmFromKey(true)` to handle this — do not remove that option from `jws.Parse` calls or valid tokens from JWKS providers that omit `alg` will be silently rejected. Regression coverage lives in `validator/validator_test.go`.

2. **JWKS cache 20% stale window**: `CachingProvider` proactively refreshes at 80% of TTL (not 100%). In the remaining 20% window, it may serve keys that were just rotated. This is intentional to avoid thundering herd. Do not change the 80% threshold without considering key-rotation timing implications.

3. **Module import path**: The module is `github.com/auth0/go-jwt-middleware/v3` — the `/v3` suffix is part of every import path. Forgetting the suffix silently pulls an older major version and produces confusing missing-symbol errors.

4. **`CachingProvider` option type-switch**: `jwks.NewCachingProvider` accepts both `ProviderOption` and `CachingProviderOption` via a type switch inside the constructor (`jwks/provider.go`). Adding a new option type requires updating that type switch — otherwise the option is silently ignored with no error.

5. **golangci-lint test exclusions**: The linter relaxes several rules for `*_test.go` (gocyclo, dupl, gosec, gocritic, revive, errcheck) and skips `examples/` entirely. A passing `make lint` does not mean test or example code is free of those issues.
