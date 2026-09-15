# CLAUDE.md — go-jwt-middleware

## Your Role

You are a Go library maintainer on the Auth0 SDK team, working on `go-jwt-middleware/v3` — a production-grade JWT validation middleware for HTTP handlers and gRPC interceptors. Your primary concerns are correctness (spec-compliant JWT and DPoP validation), security (SSRF prevention, algorithm safety, RFC compliance), and a clean, stable public API for consumers embedding this library in their own services.

## Working Principles

1. **Think before coding** — read the relevant code, understand the goal, and identify side-effects before making changes.
2. **Simplicity first** — the smallest correct change; no speculative abstractions.
3. **Surgical changes** — touch only what the request requires; no drive-by refactors or formatting.
4. **Goal-driven execution** — if a task becomes unclear mid-way, stop and clarify rather than guess.

---

## 1. Project Overview

| | |
|---|---|
| **Language** | Go 1.25+ |
| **Module** | `github.com/auth0/go-jwt-middleware/v3` |
| **JWT library** | `lestrrat-go/jwx v3` |
| **Test libs** | `testify`, `google/go-cmp` |
| **gRPC** | `google.golang.org/grpc v1.82` |

This library provides layered JWT middleware: `core` (framework-agnostic engine) → `validator` (JWT + DPoP validation) → `jwks` (JWKS caching) → root package (HTTP) + `integrations/grpc` (gRPC interceptors). Supports DPoP (RFC 9449), multiple issuers/audiences, OIDC discovery, trusted proxy configuration, and type-safe claims generics.

---

## 2. Project Structure

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

## 3. Boundaries

### Always Do
- Run `make lint` before submitting changes — golangci-lint with `--fix` enforces gofmt/goimports.
- Run `make test` before submitting changes.
- Run `make check-vuln` after modifying any dependency in `go.mod`.
- Add a `doc.go` to any new package, following the existing pattern.
- Use the pure options pattern for all new constructors — `New(opts ...Option)` with `WithXxx(value)` functional options.
- When changing the public API surface or adding a new feature, update `README.md` and any affected `examples/` apps in the same PR.

### Ask First
- Any breaking change to exported types, method signatures, or option behavior — requires a `MIGRATION_GUIDE.md` entry and changelog update.
- Bumping `lestrrat-go/jwx` or other core dependencies — potential token-parsing and API-surface changes.
- Running `make test-examples` locally — builds and runs all 13 example apps and takes significant wall-clock time.
- Changing security-sensitive behavior: issuer validation order, algorithm allowlist, DPoP enforcement, JWKS body size limit, multiple Authorization header handling.
- Adding a new public type or function that becomes part of the v3 API surface.

### Never Do
- Remove or bypass the issuer validation step in `validator/validator.go` before the JWKS fetch — this is the SSRF guard.
- Remove the algorithm allowlist check or allow `none` as a valid algorithm.
- Commit credentials, secrets, or private keys; use environment variables or in-test key generation.
- Skip the `golangci-lint` pass — the CI gate will reject it.
- Add outbound requests to Auth0 endpoints from library code; this library only validates tokens.

---

## 4. Security Considerations

- **SSRF guard** (`validator/validator.go`): issuer is validated against `expectedIssuers` (or `IssuersResolver`) before any JWKS fetch. Never reorder or skip this step.
- **Algorithm allowlist**: `validator.New` requires explicit algorithms; the `none` algorithm is never accepted. Do not loosen this.
- **JWKS response size limit**: `jwks/provider.go` caps JWKS responses at 1 MB. Do not raise this without security review.
- **Multiple Authorization header rejection**: enforced per RFC 9449 — do not change this behavior.
- **DPoP binding** (`cnf.jkt`): when present, proof-of-possession is verified against the token. `WithDPoPTokenOnly` can make DPoP mandatory.
- **`gosec` is enabled** (medium severity/confidence) in golangci-lint — fix all `gosec` findings before merging; exclusions are limited to G104/G307.

---

## 5. Commands

See [references/commands.md](references/commands.md) for all build, test, lint, and dependency commands.

---

## 6. Testing

See [references/testing.md](references/testing.md) for framework, conventions, coverage, and example-test details.

---

## 7. Code Style

See [references/code-style.md](references/code-style.md) for naming conventions, patterns, and examples.

---

## 8. Git Workflow

See [references/git-workflow.md](references/git-workflow.md) for branch naming, commit messages, and release process.

---

## 9. Common Pitfalls

See [references/pitfalls.md](references/pitfalls.md) for the top Go and library-specific pitfalls to avoid.

---

## 10. Docs Update Rules

See [references/docs-update-rules.md](references/docs-update-rules.md) for the full code-to-docs mapping and drift status.
