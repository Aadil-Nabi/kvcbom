# kvcbom — developer tasks. Requires Go 1.25+. Optional: golangci-lint, govulncheck,
# goreleaser (install separately; CI uses pinned versions).

BINARY      := kvcbom
PKG         := github.com/Aadil-Nabi/kvcbom
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
  -X $(PKG)/internal/version.Version=$(VERSION) \
  -X $(PKG)/internal/version.Commit=$(COMMIT) \
  -X $(PKG)/internal/version.Date=$(DATE)

.DEFAULT_GOAL := build
.PHONY: build install test race cover fuzz lint vet fmt tidy vuln snapshot clean help

build: ## Build the binary into ./bin
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/$(BINARY)

install: ## Install the binary into GOBIN
	CGO_ENABLED=0 go install -trimpath -ldflags '$(LDFLAGS)' ./cmd/$(BINARY)

test: ## Run all tests
	go test ./...

race: ## Run tests with the race detector
	go test -race ./...

cover: ## Run tests with coverage summary
	go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1

fuzz: ## Run each fuzz target briefly (smoke)
	go test ./pkg/ingest/cbom     -run='^$$' -fuzz=FuzzParseCBOMJSON    -fuzztime=10s
	go test ./pkg/ingest/cbom     -run='^$$' -fuzz=FuzzParseCBOMXML     -fuzztime=10s
	go test ./pkg/ingest/context  -run='^$$' -fuzz=FuzzParseContext     -fuzztime=10s
	go test ./pkg/ingest/register -run='^$$' -fuzz=FuzzParseRegisterCSV -fuzztime=10s

lint: ## Run golangci-lint (must be installed)
	golangci-lint run

vet: ## Run go vet
	go vet ./...

fmt: ## Format the code
	gofmt -w .

tidy: ## Tidy go.mod/go.sum
	go mod tidy

vuln: ## Run govulncheck (must be installed)
	govulncheck ./...

snapshot: ## Build a local release snapshot with GoReleaser (must be installed)
	goreleaser release --snapshot --clean

clean: ## Remove build artifacts
	rm -rf bin dist coverage.out

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n", $$1, $$2}'
