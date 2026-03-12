GO ?= go
PROTOC ?= protoc

.PHONY: fmt test vet proto migrate run-api run-worker

fmt:
	$(GO) fmt ./...

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

proto:
	PATH="$(shell $(GO) env GOPATH)/bin:$$PATH" $(PROTOC) --proto_path=. --go_out=. --go_opt=paths=source_relative --connect-go_out=. --connect-go_opt=paths=source_relative proto/asb/v1/broker.proto

migrate:
	$(GO) run ./cmd/asb-migrate

run-api:
	$(GO) run ./cmd/asb-api

run-worker:
	$(GO) run ./cmd/asb-worker
