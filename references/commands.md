# Commands

## Build
```bash
go build ./...
```

## Test (unit — safe, no credentials required)
```bash
make test
# equivalent:
go test -cover -covermode=atomic -coverprofile=coverage.out ./...
```

Filter to specific tests:
```bash
make test FILTER=TestValidateToken
```

Add `-race` to detect data races:
```bash
go test -race -cover ./...
```

## Lint (with auto-fix)
```bash
make lint
# golangci-lint run -v --fix
```

## Vulnerability check (run after modifying go.mod)
```bash
make check-vuln
# govulncheck ./...
```

## Download / vendor dependencies
```bash
make deps
# go mod vendor -v
```

## Test examples — integration tier (ask first; slow)
```bash
make test-examples
# For each examples/*/ directory:
#   cd <dir> && go mod tidy && go test -v -tags=integration ./...
# Runs all 13 example apps; exits non-zero on first failure.
```
