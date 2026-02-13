.PHONY: all prereqs build build-all clean test test-cover cover-html vet lint vuln fmt certs generate-local download-letsencrypt shellcheck help

.DEFAULT_GOAL := help

# Ensure Homebrew-installed tools are available when `make` runs under a
# non-login shell (common on macOS). Harmless on non-Homebrew systems.
export PATH := /opt/homebrew/bin:/usr/local/bin:$(PATH)

BINARY_NAME := certconv
VERSION ?= dev
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

BUILDFLAGS := -trimpath
LDFLAGS := -ldflags "-w -s -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"

GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOVET := $(GOCMD) vet
GOTESTPKGS := $(shell $(GOCMD) list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./... | sed '/^$$/d')

all: test build ## Run tests then build

prereqs: ## Check local prerequisites for common targets
	@./scripts/prereqs.sh

build: ## Build for the current platform
	@mkdir -p bin
	CGO_ENABLED=0 $(GOBUILD) $(BUILDFLAGS) $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/certconv

build-all: ## Cross-compile binaries (linux/darwin/windows; amd64/arm64 where applicable)
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 $(GOBUILD) $(BUILDFLAGS) $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64  ./cmd/certconv
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 $(GOBUILD) $(BUILDFLAGS) $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64  ./cmd/certconv
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 $(GOBUILD) $(BUILDFLAGS) $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64   ./cmd/certconv
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 $(GOBUILD) $(BUILDFLAGS) $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64   ./cmd/certconv
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) $(BUILDFLAGS) $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe ./cmd/certconv

clean: ## Remove build artifacts
	rm -rf bin coverage.out

test: ## Run tests
	$(GOTEST) -v -race $(GOTESTPKGS)

test-cover: ## Run tests with coverage (writes coverage.out)
	@# Coverage + -race is not reliably supported across all Go distributions/toolchains.
	@# Keep this target deterministic and portable; keep -race in `make test`.
	$(GOTEST) -v -coverprofile=coverage.out ./...
	@echo "Wrote coverage.out"

cover-html: test-cover ## Generate coverage.html from coverage.out
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Wrote coverage.html"

vet: ## Run go vet
	$(GOVET) ./...

lint: ## Run golangci-lint (installs if missing)
	@which golangci-lint >/dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

vuln: ## Run govulncheck (installs if missing)
	@which govulncheck >/dev/null || (echo "Installing govulncheck..." && go install golang.org/x/vuln/cmd/govulncheck@latest)
	govulncheck ./...

fmt: ## Format code and tidy modules
	$(GOCMD) fmt ./...
	$(GOCMD) mod tidy

certs: ## Generate sample certs in ./certs (used for manual testing)
	@mkdir -p certs
	@openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
	  -keyout certs/example.key -out certs/example.pem \
	  -subj "/CN=example.local/O=CertConv" \
	  -addext "subjectAltName = DNS:example.local,DNS:localhost" \
	  -addext "keyUsage = digitalSignature" \
	  -addext "extendedKeyUsage = serverAuth" >/dev/null 2>&1
	@chmod 600 certs/example.key
	@openssl pkcs12 -export -out certs/example.pfx -in certs/example.pem \
	  -inkey certs/example.key -passout pass: >/dev/null 2>&1
	@openssl pkcs12 -export -out certs/example-pass.pfx -in certs/example.pem \
	  -inkey certs/example.key -passout pass:testpass >/dev/null 2>&1
	@echo "Generated sample certs in ./certs"

generate-local: ## Run scripts/generate-local.sh
	@./scripts/generate-local.sh

download-letsencrypt: ## Run scripts/download-letsencrypt.sh
	@./scripts/download-letsencrypt.sh

shellcheck: ## Lint shell scripts (legacy scripts are kept for reference)
	shellcheck scripts/*.sh legacy/*.sh

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'
