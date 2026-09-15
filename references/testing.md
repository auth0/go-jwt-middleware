# Testing

## Framework
- Assertions: `testify/assert` (non-fatal) and `testify/require` (fatal-on-failure)
- Deep equality: `google/go-cmp` for structured diffs
- HTTP simulation: `net/http/httptest`
- No external services or credentials required for the default `make test` suite

## Running tests
```bash
make test                              # All packages, with coverage
make test FILTER=TestCachingProvider   # Subset by name
go test -race -cover ./...             # Race detector enabled
```

## Test structure
Table-driven with `t.Parallel()` inside each sub-test:
```go
tests := []struct {
    name    string
    token   string
    wantErr bool
}{
    {name: "valid", token: validToken},
    {name: "expired", token: expiredToken, wantErr: true},
}
for _, tc := range tests {
    t.Run(tc.name, func(t *testing.T) {
        t.Parallel()
        // ...
    })
}
```

Unit tests live in `*_test.go` alongside source, in either the same package or the `_test` package suffix. Test helpers must be goroutine-safe because sub-tests run in parallel.

## Coverage
`make test` writes `coverage.out`. CI uploads it to Codecov. The golangci-lint config excludes `*_test.go` from several linters (gocyclo, dupl, gosec, gocritic, revive, errcheck) — test files may not be lint-clean even if `make lint` passes.

## Integration / example tests (ask first)
Each `examples/*/` app has a `*_integration_test.go` or `main_test.go` guarded by `-tags=integration`. `make test-examples` runs them all sequentially — it starts local HTTP/gRPC servers and exercises real request flows using locally generated keys. Does not require Auth0 tenant credentials, but takes significant wall-clock time.
