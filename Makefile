.PHONY: build test lint clean

BINARY := tass
BUILD_DIR := .
CMD := ./cmd/tass

build:
	CGO_ENABLED=1 go build -o $(BUILD_DIR)/$(BINARY) $(CMD)

test:
	go test ./...

lint:
	go vet ./...

clean:
	rm -f $(BUILD_DIR)/$(BINARY)
