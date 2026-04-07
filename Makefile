.PHONY: build test lint clean generate

BINARY     := tass
BUILD_DIR  := .
CMD        := ./cmd/tass

VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X main.version=$(VERSION) \
           -X main.commit=$(COMMIT) \
           -X main.buildDate=$(BUILD_DATE) \
           -s -w

build:
	CGO_ENABLED=1 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) $(CMD)

generate:
	templ generate

test:
	go test ./...

lint:
	go vet ./...

clean:
	rm -f $(BUILD_DIR)/$(BINARY)
