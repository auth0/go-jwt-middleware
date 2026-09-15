# Git Workflow

## Branches
- **Main branch**: `master`
- **Feature / fix branches**: descriptive kebab-case names, e.g. `add-token-exchange-support`, `fix-jwks-cache-race`
- **Release branches**: `release/<version>` — merging to `master` triggers the release workflow

## Version
The version string lives in the `.version` file at the repo root. The release CI reads this to tag the GitHub release. Update `.version` when preparing a release branch.

## Commit messages
No enforced conventional-commit prefix in CI, but follow the CHANGELOG format:
```
feat: add WithRegisteredClaimsValidator option
fix: resolve JWKS key selection for keys omitting alg member
```

## Pull requests
- Target `master`
- Include a `CHANGELOG.md` entry under `[Unreleased]` for every user-visible change
- For breaking changes: add a `MIGRATION_GUIDE.md` section and bump the major version in `.version` and the module path

## Dependabot
Daily gomod + github-actions updates run automatically via `.github/dependabot.yml`. Review and merge routine bumps promptly; for `lestrrat-go/jwx` bumps, run `make test` and `make check-vuln` before merging.

## CI gates (all must pass before merge)
- `test.yaml` — unit tests on Linux / macOS / Windows + example tests on Linux
- `lint.yaml` — golangci-lint v2.6.2
- `govulncheck.yml` — vulnerability scan
- `sca_scan.yml` — Snyk SCA
