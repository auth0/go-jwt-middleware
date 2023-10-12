.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[%a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

#-----------------------------------------------------------------------------------------------------------------------
# Dependencies
#-----------------------------------------------------------------------------------------------------------------------
.PHONY: deps

deps: ## Download dependencies
	@echo "==> Downloading dependencies to vendor folder..."
	@go mod vendor -v

$(GO_BIN)/golangci-lint:
	${call print, "Installing golangci-lint"}
	@go install -v github.com/golangci/golangci-lint/cmd/golangci-lint@latest

$(GO_BIN)/govulncheck:
	@go install -v golang.org/x/vuln/cmd/govulncheck@latest

#-----------------------------------------------------------------------------------------------------------------------
# Testing
#-----------------------------------------------------------------------------------------------------------------------
.PHONY: test

test: ## Run tests. To run a specific test pass the FILTER var. Usage `make test FILTER="Test_invalidError"`
	@echo "==> Running tests..."
	@go test \
		-run "$(FILTER)" \
		-cover \
		-covermode=atomic \
		-coverprofile=coverage.out \
		./...

#-----------------------------------------------------------------------------------------------------------------------
# Checks
#-----------------------------------------------------------------------------------------------------------------------
.PHONY: lint check-vuln

lint: $(GO_BIN)/golangci-lint ## Run linting on the go files
	@echo "==> Running linting on the library with golangci-lint..."
	@golangci-lint run -v --fix

check-vuln: $(GO_BIN)/govulncheck ## Check for vulnerabilities
	@echo "==> Checking for vulnerabilities..."
	@govulncheck ./...
