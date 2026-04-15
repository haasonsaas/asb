GO ?= go

.PHONY: fmt test vet lint install-hooks proto proto-check migrate run-api run-worker

fmt:
	$(GO) fmt ./...

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

lint: vet

proto:
	bash scripts/sync-proto.sh

proto-check:
	bash scripts/sync-proto.sh --check

migrate:
	$(GO) run ./cmd/asb-migrate

run-api:
	$(GO) run ./cmd/asb-api

run-worker:
	$(GO) run ./cmd/asb-worker

install-hooks:
	cp scripts/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed"
