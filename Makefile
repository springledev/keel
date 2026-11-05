# Keel — vet, test and lint. Pure Go, no cgo.

GO ?= go

.PHONY: vet test cover lint
vet:
	CGO_ENABLED=0 $(GO) vet ./...

test:
	$(GO) test ./... -race

cover:
	$(GO) test ./... -race -coverprofile=coverage.out
	$(GO) tool cover -func=coverage.out

lint: ## same golangci-lint version as CI
	golangci-lint run ./...
