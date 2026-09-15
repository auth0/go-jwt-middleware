# Docs Update Rules

## Tracked Documents

| Doc | Covers | Status |
|-----|--------|--------|
| `README.md` | Installation, quick-start, usage, configuration, error handling, examples index | present |
| `examples/` (13 apps) | Runnable sample apps: echo, gin, iris, grpc, DPoP variants, multi-issuer, dynamic issuer | present |
| `EXAMPLES.md` | Standalone inline code samples | ❌ missing |

## Code-to-Docs Mapping (library)

| When this changes | Update these docs |
|-------------------|-------------------|
| Exported type, function, or method added, removed, or renamed | `README.md` (usage / configuration sections) + affected `examples/` apps |
| Constructor option (`WithXxx`) added, removed, or renamed | `README.md` (configuration section) |
| JWT validation behavior (issuer, audience, algorithm, DPoP, RFC 8693 claims) | `README.md` (configuration / usage) + `examples/` apps demonstrating that behavior |
| Go version requirement or module path changed | `README.md` (Getting Started / Installation) |
| New framework integration added | `README.md` (examples section) + new app under `examples/` |
| Error type or `WWW-Authenticate` format changed | `README.md` (Error Handling section) |

> When you touch code that maps to a doc above, update that doc **in the same PR** — do not defer.

## Notes on `examples/` apps
Each example has its own `go.mod`. When the public API changes, update both the example source and its `go.mod`. `make test-examples` catches broken examples before merge.

## On `EXAMPLES.md`
No standalone `EXAMPLES.md` exists. If inline quick-start snippets beyond the `examples/` apps are needed, create `EXAMPLES.md` and add it to the tracking table above.
