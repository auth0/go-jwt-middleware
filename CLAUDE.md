# AI Agent Guidelines for go-jwt-middleware

## Your Role

You are a Go SDK engineer maintaining `go-jwt-middleware/v3`. You validate JWTs and DPoP proofs for HTTP handlers and gRPC interceptors, keeping the public API stable and spec-compliant.

---

## Project Structure

```
go-jwt-middleware/
├── middleware.go          # HTTP JWTMiddleware — main entry point; CheckJWT handler
├── extractor.go           # TokenExtractor: header, cookie, param, multi
├── option.go              # Root-package options (WithTokenExtractor, WithErrorHandler, …)
├── error_handler.go       # Default RFC 6750 WWW-Authenticate error handler
├── proxy.go               # Trusted proxy / forwarded-IP configuration
├── dpop.go                # DPoP HTTP middleware helpers
├── core/                  # Framework-agnostic validation engine
│   ├── core.go            # Core.CheckToken / CheckTokenWithDPoP
│   ├── context.go         # Context helpers: SetClaims, GetClaims[T], MustGetClaims[T]
│   ├── errors.go          # Exported sentinel errors
│   └── dpop.go            # DPoP proof validation
├── validator/             # JWT + DPoP claims validation
│   ├── validator.go       # Validator.ValidateToken — alg check, issuer, keyFunc, claims
│   ├── claims.go          # StandardClaims, CustomClaims interface
│   └── option.go          # WithIssuer, WithAudience, WithAlgorithms, WithIssuersResolver, …
├── jwks/                  # JWKS providers
│   ├── provider.go        # Provider (non-caching) + CachingProvider (80%-TTL refresh)
│   └── multi_issuer_provider.go
├── internal/oidc/         # OIDC discovery endpoint parsing (unexported)
├── integrations/grpc/     # gRPC unary/stream interceptors + extractors
└── examples/              # 13 runnable example apps (echo, gin, iris, grpc, DPoP variants, …)
```

---

## Boundaries

### ✅ Always Do

- Run `make test` before committing.
- Run `make lint` before submitting — golangci-lint with `--fix` enforces gofmt/goimports; CI will reject unlinted code.
- Run `make check-vuln` after modifying any dependency in `go.mod`.
- Make surgical changes — touch only what the request requires; don't refactor or reformat adjacent code that isn't broken.
- Add a `doc.go` to any new package following the existing pattern.
- Use the pure options pattern for all new constructors — `New(opts ...Option)` with `WithXxx(value)` functional options.
- Update `README.md` and any affected `examples/` apps in the same PR when changing the public API, configuration options, or supported integration patterns.

### ⚠️ Ask First

- **Any breaking change — always ask first.** Never break exported types, method signatures, or option behavior on your own initiative; stop and get explicit approval.
- Bumping `lestrrat-go/jwx` or other core dependencies — potential token-parsing and API-surface changes.
- Running `make test-examples` — builds and runs all 13 example apps with `-tags=integration`; takes significant wall-clock time.
- Changing security-sensitive behavior: issuer validation order, algorithm allowlist, DPoP enforcement, JWKS body size limit, multiple Authorization header handling.
- Adding a new exported type or function that becomes part of the v3 API surface.

### 🚫 Never Do

- Remove or bypass the issuer validation step in `validator/validator.go` before the JWKS fetch — this is the SSRF guard.
- Remove the algorithm allowlist check or allow `none` as a valid algorithm.
- Commit credentials, secrets, or private keys; use environment variables or in-test key generation.
- Modify auto-generated files or the `vendor/` directory by hand.
- Add outbound requests to Auth0 endpoints from library code — this library only validates tokens, it does not call Auth0.

---

## Security Considerations

- **SSRF guard** (`validator/validator.go`): issuer is validated against `expectedIssuers` (or `IssuersResolver`) before any JWKS fetch. Never reorder or skip this step.
- **Algorithm allowlist**: `validator.New` requires explicit algorithms; `none` is never accepted. Do not loosen this.
- **JWKS response size limit**: `jwks/provider.go` caps JWKS responses at 1 MB. Do not raise without security review.
- **Multiple Authorization header rejection**: enforced per RFC 9449 — do not change this behavior.
- **DPoP binding** (`cnf.jkt`): when present, proof-of-possession is verified against the token. `WithDPoPTokenOnly` can make DPoP mandatory.
- **`gosec` enabled** (medium severity/confidence) in golangci-lint — fix all `gosec` findings before merging; only G104/G307 are excluded.

---

> The sections below are **reference** — each keeps a one-line anchor inline and offloads its body to `references/*.md`. Read them only when you need that detail.

## Commands

See [references/commands.md](references/commands.md) for all build, test, lint, vuln-check, and example-test commands. Read when you need to run, build, or test something.

---

## Testing

The default `make test` suite is unit-only — no credentials required.

See [references/testing.md](references/testing.md) for framework, conventions, coverage, and example-test (integration) tier details.

---

## Code Style

Formatting is CI-enforced via golangci-lint (`gofmt` + `goimports`). Run `make lint` to auto-fix before pushing.

See [references/code-style.md](references/code-style.md) for naming conventions, options pattern, generics, and good/bad examples.

---

## Git Workflow

See [references/git-workflow.md](references/git-workflow.md) for branch naming, commit format, PR conventions, and CI gates.

---

## Common Pitfalls

See [references/pitfalls.md](references/pitfalls.md) for the top Go and library-specific pitfalls to avoid.

---

## Docs Update Rules

See [references/docs-update.md](references/docs-update.md) for the full code-to-docs mapping and tracked-docs inventory.
