.PHONY: build test test-short test-race vet fmt lint tidy check

GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BIN     ?= bin/vnm

# A static binary: nodes run different distributions and nothing is installed
# beside it but nft, ip and the kernel's WireGuard.
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN) ./cmd/vnm

# The full suite includes the flow stand (test/flowstand): real rulesets in
# unprivileged network namespaces. It needs unshare and nft, and skips itself
# where they are missing.
test:
	$(GO) test ./...

# Unit tests only — no namespaces, no traffic.
test-short:
	$(GO) test -short ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

lint:
	golangci-lint run

tidy:
	$(GO) mod tidy

# The gate before a build reaches a node: a wrong ruleset cuts a node off from
# its users, and there is no staging fleet.
check: fmt vet test
