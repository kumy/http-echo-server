MODULE   := github.com/kumy/https-echo-server
BINARY   := https-echo-server
BIN_DIR  := bin
IMAGE    := ghcr.io/kumy/https-echo-server

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS  := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

GOFLAGS  := -trimpath

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## --- Build ---

.PHONY: build
build: ## Build the binary into ./bin
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) ./cmd/$(BINARY)

.PHONY: run
run: build ## Build and run the server
	./$(BIN_DIR)/$(BINARY)

.PHONY: clean
clean: ## Remove build artifacts, coverage and docs output
	rm -rf $(BIN_DIR) dist site coverage.out coverage.html

## --- Quality ---

.PHONY: test
test: ## Run tests with race detector and coverage
	go test -race -shuffle=on -coverprofile=coverage.out -covermode=atomic ./...

.PHONY: cover
cover: test ## Open HTML coverage report
	go tool cover -html=coverage.out -o coverage.html
	@echo "coverage report: coverage.html"

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run ./...

.PHONY: fmt
fmt: ## Format code (gofmt + goimports via golangci-lint)
	golangci-lint fmt ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: tidy
tidy: ## go mod tidy
	go mod tidy

## --- Docker ---

.PHONY: docker-build
docker-build: ## Build the multi-stage docker image
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

.PHONY: docker-run
docker-run: docker-build ## Run the docker image (ports 8080/8443)
	docker run --rm -t -p 8080:8080 -p 8443:8443 $(IMAGE):latest

## --- Docs (zensical) ---

.PHONY: docs-serve
docs-serve: ## Live-preview docs at http://localhost:8000 (needs uv or pip install zensical)
	uvx zensical serve || zensical serve

.PHONY: docs-build
docs-build: ## Build the static docs site into ./site
	uvx zensical build --clean || zensical build --clean

## --- Release ---

.PHONY: snapshot
snapshot: ## Local goreleaser snapshot build (no publish)
	goreleaser release --snapshot --clean

.PHONY: tools
tools: ## Install dev tools (golangci-lint, goreleaser)
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	go install github.com/goreleaser/goreleaser/v2@latest
