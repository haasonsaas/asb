GO ?= go

.PHONY: fmt test vet proto migrate run-api run-worker

fmt:
	$(GO) fmt ./...

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

proto:
	buf generate

migrate:
	$(GO) run ./cmd/asb-migrate

run-api:
	$(GO) run ./cmd/asb-api

run-worker:
	$(GO) run ./cmd/asb-worker
