# Docs Update Rules

## Tracked Documents

| Doc | Status |
|-----|--------|
| `README.md` | ✅ current (aligned with v3.3.0 — RFC 8693, DPoP, gRPC, generics all documented) |
| `examples/` (13 apps) | ✅ current (covers echo, gin, iris, grpc, DPoP variants, multi-issuer, dynamic issuer) |
| `EXAMPLES.md` | ❌ missing — no standalone EXAMPLES.md; code examples live in `examples/` apps |

## Code-to-Docs Mapping (library)

| When this changes | Update these docs |
|-------------------|-------------------|
| Public API: exported type, function, or method added, removed, or renamed | `README.md` (usage / configuration sections) + affected `examples/` apps |
| Constructor option (`WithXxx`) added, removed, or renamed | `README.md` (configuration section) |
| JWT validation behavior (issuer, audience, algorithm, DPoP, RFC 8693 claims) | `README.md` (configuration / usage), `examples/` apps that demonstrate that behavior |
| Go version requirement or module path changed | `README.md` (Getting Started / Installation) |
| New framework integration added | `README.md` (examples section) + new app under `examples/` |
| Error type or `WWW-Authenticate` format changed | `README.md` (Error Handling section) |
| New installation step or `go get` path changed | `README.md` (Getting Started) |

## Notes on `examples/` apps
Each example has its own `go.mod` pinning the middleware version. When the public API changes, update both the example source and its `go.mod` to use the new API. `make test-examples` will catch broken examples before merge.

## On `EXAMPLES.md`
If standalone code snippets beyond the `examples/` apps become necessary (e.g., inline quick-start samples not backed by a runnable app), create `EXAMPLES.md` and add it to this tracking table.
