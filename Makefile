# Eclipse SCINTX developer entrypoints. Prefer `make <target>` or `./scripts/<name>.sh`.
# Run `make help` for the list.

.PHONY: help fmt vet lint test test-race build run demo schemas check image-check tidy clean hooks

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make <target>\n\nTargets:\n"} \
		/^[a-zA-Z0-9_-]+:.*?##/ { printf "  %-12s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

fmt: ## Format Go sources (gofmt -w)
	./scripts/fmt.sh

vet: ## Run go vet
	./scripts/vet.sh

lint: ## Run golangci-lint (rules in .golangci.yml)
	./scripts/lint.sh

test: ## Run go test ./...
	./scripts/test.sh

test-race: ## Run go test -race (falls back without CGO)
	./scripts/test-race.sh

build: ## Build bin/scintx
	./scripts/build.sh

run: ## Build and run the HTTP gateway server
	./scripts/run.sh

demo: ## Run deterministic offline demonstration (startup, submit, status, validation error)
	./scripts/demo.sh

schemas: ## Validate JSON Schema fixtures
	./scripts/schemas.sh

check: ## Local CI: fmt, headers, vet, lint, tests, schemas
	./scripts/check.sh

# Not part of "check": it needs Docker (or Podman) and an image build is slow.
# CI runs it as its own job (see the "image" job in .github/workflows/ci.yml).
image-check: ## Build the container image and wait until it reports healthy
	./scripts/image-check.sh

tidy: ## go mod tidy
	./scripts/tidy.sh

clean: ## Remove bin/ and test cache
	./scripts/clean.sh

hooks: ## Install git pre-commit hook (sets local core.hooksPath)
	./scripts/install-hooks.sh
