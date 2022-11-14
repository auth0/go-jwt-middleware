.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[%a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: test
test: ## Run tests.
	go test -race -cover -covermode=atomic -coverprofile=coverage.out ./...

.PHONY: lint
lint: ## Run golangci-lint.
	golangci-lint run -v --timeout=5m

$(GO_BIN)/govulncheck:
	@go install -v golang.org/x/vuln/cmd/govulncheck@latest

.PHONY: check-vuln
check-vuln: $(GO_BIN)/govulncheck ## Check for vulnerabilities.
	@govulncheck -v ./...
