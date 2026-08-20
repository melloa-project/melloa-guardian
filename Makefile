PREVIEW_STATE_DIR ?= $(CURDIR)/state/local-preview

.PHONY: build check preview-state preview-state-clean preview-state-test test

build:
	go build -trimpath -o bin/guardianctl ./cmd/guardianctl

test:
	go test ./...

check:
	test -z "$$(gofmt -l $$(find . -name '*.go' -type f))"
	go vet ./...
	go test ./...
	bash -n tools/preview_state.sh tools/test_preview_state.sh

preview-state: build
	bash tools/preview_state.sh create "$(PREVIEW_STATE_DIR)" "$(CURDIR)/bin/guardianctl"

preview-state-clean:
	bash tools/preview_state.sh clean "$(PREVIEW_STATE_DIR)"

preview-state-test: build
	bash tools/test_preview_state.sh "$(CURDIR)/bin/guardianctl" "$(CURDIR)/tools/preview_state.sh"
