.PHONY: build check test

build:
	go build -trimpath -o bin/guardianctl ./cmd/guardianctl

test:
	go test ./...

check:
	test -z "$$(gofmt -l $$(find . -name '*.go' -type f))"
	go vet ./...
	go test ./...
