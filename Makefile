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
	${call print, "Installing golangci-lint v2.6.2"}
	@go install -v github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.2

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

.PHONY: test-examples
test-examples: ## Run integration tests for all examples. Use SKIP_EXAMPLES="pattern" to skip or ONLY_EXAMPLES="pattern" to run only matching
	@echo "==> Running example integration tests..."
	@for dir in examples/*/; do \
		if [ -n "$(ONLY_EXAMPLES)" ] && ! echo "$$dir" | grep -qE "$(ONLY_EXAMPLES)"; then \
			continue; \
		fi; \
		if [ -n "$(SKIP_EXAMPLES)" ] && echo "$$dir" | grep -qE "$(SKIP_EXAMPLES)"; then \
			echo "Skipping $$dir (matches SKIP_EXAMPLES pattern)..."; \
			continue; \
		fi; \
		if [ -f "$$dir/main_integration_test.go" ] || [ -f "$$dir/main_test.go" ]; then \
			echo "Testing $$dir..."; \
			(cd "$$dir" && go mod tidy && go test -v -tags=integration ./...) || exit 1; \
		fi; \
	done
	@echo "==> All example tests passed!"

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
