# Makefile for gRPC Test Server
# ================================

# Variables
BINARY_NAME := grpc-server
BIN_DIR := bin
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GO_VERSION := $(shell go version | cut -d ' ' -f 3)

# Build flags
LDFLAGS := -ldflags "-s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"

# Docker variables
DOCKER_REGISTRY ?= docker.io
DOCKER_REPO ?= alexey/grpc-example
DOCKER_TAG ?= $(VERSION)
DOCKER_IMAGE := $(DOCKER_REGISTRY)/$(DOCKER_REPO):$(DOCKER_TAG)

# Go variables
GOBIN := $(shell go env GOPATH)/bin
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

# Coverage variables
COVERAGE_DIR := coverage
COVERAGE_UNIT := $(COVERAGE_DIR)/unit.out
COVERAGE_FUNCTIONAL := $(COVERAGE_DIR)/functional.out
COVERAGE_COMBINED := $(COVERAGE_DIR)/combined.out
COVERAGE_HTML := $(COVERAGE_DIR)/coverage.html

# Proto variables
PROTO_DIR := api/proto
PROTO_OUT := pkg/api

# Tools
GOLANGCI_LINT_VERSION := v2.1.6
PROTOC_GEN_GO_VERSION := v1.36.6
PROTOC_GEN_GO_GRPC_VERSION := v1.5.1

.PHONY: all proto build test test-unit test-functional test-coverage lint vulncheck docker-build docker-push clean help tools \
       test-env-up test-env-down test-env-logs test-env-clean test-env-status test-env-wait \
       test-integration test-e2e test-performance generate-certs

# Default target
all: proto lint test build

##@ Development

proto: ## Generate protobuf code
	@echo "==> Generating protobuf code..."
	@mkdir -p $(PROTO_OUT)/v1
	protoc --proto_path=$(PROTO_DIR) \
		--go_out=$(PROTO_OUT) --go_opt=paths=source_relative \
		--go-grpc_out=$(PROTO_OUT) --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/v1/*.proto
	@echo "==> Protobuf generation complete"

build: ## Build binary to bin/
	@echo "==> Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/server
	@echo "==> Binary built: $(BIN_DIR)/$(BINARY_NAME)"

build-linux: ## Build binary for linux/amd64
	@echo "==> Building $(BINARY_NAME) for linux/amd64..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/server
	@echo "==> Binary built: $(BIN_DIR)/$(BINARY_NAME)-linux-amd64"

run: build ## Run the server locally
	@echo "==> Running $(BINARY_NAME)..."
	./$(BIN_DIR)/$(BINARY_NAME)

##@ Testing

test: test-unit test-functional ## Run all tests

test-unit: ## Run unit tests with coverage
	@echo "==> Running unit tests..."
	@mkdir -p $(COVERAGE_DIR)
	go test -v -race -coverprofile=$(COVERAGE_UNIT) -covermode=atomic ./internal/...
	@echo "==> Unit tests complete"

test-functional: ## Run functional tests with coverage
	@echo "==> Running functional tests..."
	@mkdir -p $(COVERAGE_DIR)
	go test -v -race -tags=functional -coverprofile=$(COVERAGE_FUNCTIONAL) -covermode=atomic ./test/functional/...
	@echo "==> Functional tests complete"

test-coverage: test-unit test-functional ## Generate combined coverage report
	@echo "==> Generating combined coverage report..."
	@mkdir -p $(COVERAGE_DIR)
	@echo "mode: atomic" > $(COVERAGE_COMBINED)
	@tail -n +2 $(COVERAGE_UNIT) >> $(COVERAGE_COMBINED) 2>/dev/null || true
	@tail -n +2 $(COVERAGE_FUNCTIONAL) >> $(COVERAGE_COMBINED) 2>/dev/null || true
	go tool cover -html=$(COVERAGE_COMBINED) -o $(COVERAGE_HTML)
	@go tool cover -func=$(COVERAGE_COMBINED) | tail -1
	@echo "==> Coverage report: $(COVERAGE_HTML)"

##@ Code Quality

lint: ## Run golangci-lint
	@echo "==> Running linter..."
	golangci-lint run --timeout 5m ./...
	@echo "==> Linting complete"

vulncheck: ## Run govulncheck
	@echo "==> Running vulnerability check..."
	govulncheck ./...
	@echo "==> Vulnerability check complete"

fmt: ## Format code
	@echo "==> Formatting code..."
	go fmt ./...
	goimports -w .
	@echo "==> Formatting complete"

vet: ## Run go vet
	@echo "==> Running go vet..."
	go vet ./...
	@echo "==> Vet complete"

##@ Docker

docker-build: ## Build Docker image
	@echo "==> Building Docker image $(DOCKER_IMAGE)..."
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		-t $(DOCKER_IMAGE) \
		-t $(DOCKER_REGISTRY)/$(DOCKER_REPO):latest \
		.
	@echo "==> Docker image built: $(DOCKER_IMAGE)"

docker-push: ## Push Docker image to registry
	@echo "==> Pushing Docker image $(DOCKER_IMAGE)..."
	docker push $(DOCKER_IMAGE)
	docker push $(DOCKER_REGISTRY)/$(DOCKER_REPO):latest
	@echo "==> Docker image pushed"

docker-run: docker-build ## Run Docker container locally
	@echo "==> Running Docker container..."
	docker run --rm -p 50051:50051 $(DOCKER_IMAGE)

docker-size: docker-build ## Show Docker image size
	@docker images $(DOCKER_IMAGE) --format "{{.Size}}"

##@ Tools

tools: ## Install development tools
	@echo "==> Installing development tools..."
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)
	go install golang.org/x/tools/cmd/goimports@latest
	@echo "==> Tools installed"

##@ Test Environment (docker-compose)

COMPOSE_FILE := test/docker-compose/docker-compose.yml
COMPOSE_ENV := test/docker-compose/.env.test
COMPOSE_CMD := docker compose -f $(COMPOSE_FILE) --env-file $(COMPOSE_ENV) -p grpc-test

test-env-up: ## Start test environment (Vault, Keycloak, gRPC server)
	@echo "==> Starting test environment..."
	$(COMPOSE_CMD) up -d --build
	@echo "==> Test environment started"
	@echo "    Vault:    http://localhost:$${VAULT_HOST_PORT:-8200}"
	@echo "    Keycloak: http://localhost:$${KC_HOST_PORT:-8090}"
	@echo "    gRPC:     localhost:$${GRPC_HOST_PORT:-50051}"

test-env-down: ## Stop test environment
	@echo "==> Stopping test environment..."
	$(COMPOSE_CMD) down
	@echo "==> Test environment stopped"

test-env-logs: ## Show test environment logs (use SVC=<name> for a single service)
	$(COMPOSE_CMD) logs -f $(SVC)

test-env-clean: ## Stop test environment and remove volumes
	@echo "==> Cleaning test environment (removing volumes)..."
	$(COMPOSE_CMD) down -v --remove-orphans
	@echo "==> Test environment cleaned"

test-env-status: ## Show test environment service status
	$(COMPOSE_CMD) ps

test-env-wait: ## Wait for all test services to be healthy
	@echo "==> Waiting for test services..."
	@./test/docker-compose/scripts/wait-for-services.sh

test-integration: test-env-up test-env-wait ## Run integration tests against test environment
	@echo "==> Running integration tests..."
	@mkdir -p $(COVERAGE_DIR)
	go test -v -race -tags=integration -coverprofile=$(COVERAGE_DIR)/integration.out -covermode=atomic ./test/integration/... || \
		($(COMPOSE_CMD) logs && exit 1)
	@echo "==> Integration tests complete"

test-e2e: test-env-up test-env-wait ## Run end-to-end tests against test environment
	@echo "==> Running e2e tests..."
	@mkdir -p $(COVERAGE_DIR)
	go test -v -race -tags=e2e -timeout 5m -coverprofile=$(COVERAGE_DIR)/e2e.out -covermode=atomic ./test/e2e/... || \
		($(COMPOSE_CMD) logs && exit 1)
	@echo "==> E2E tests complete"

test-performance: test-env-up test-env-wait ## Run performance tests against test environment
	@echo "==> Running performance tests..."
	go test -v -tags=performance -timeout 10m -run TestPerformance ./test/performance/... || \
		($(COMPOSE_CMD) logs && exit 1)
	@echo "==> Performance tests complete"

generate-certs: ## Generate self-signed certificates for local testing (no Vault)
	@echo "==> Generating self-signed certificates..."
	@./test/docker-compose/scripts/generate-certs.sh ./certs
	@echo "==> Certificates generated in ./certs"

##@ Cleanup

clean: ## Clean build artifacts
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -rf $(COVERAGE_DIR)
	rm -f coverage.out coverage.html
	go clean -cache -testcache
	@echo "==> Clean complete"

##@ Dependencies

deps: ## Download dependencies
	@echo "==> Downloading dependencies..."
	go mod download
	go mod verify
	@echo "==> Dependencies downloaded"

deps-update: ## Update dependencies
	@echo "==> Updating dependencies..."
	go get -u ./...
	go mod tidy
	@echo "==> Dependencies updated"

##@ Help

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

# Print variables for debugging
print-%:
	@echo $* = $($*)
