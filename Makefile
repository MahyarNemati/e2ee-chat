# CGO is disabled for local builds because this host's macOS SDK cannot link
# cgo. It must stay enabled in CI, where -race needs it.
export CGO_ENABLED ?= 0

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test race vectors demo lint tidy clean docker

all: build test

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/e2ee-chat ./cmd/e2ee-chat

test:
	go test ./... -count=1

# The race detector needs cgo, so this overrides the default above.
race:
	CGO_ENABLED=1 go test -race ./... -count=1

# Just the known-answer tests, verbosely, so you can see which vectors ran.
vectors:
	go test ./internal/primitives/ -run Vector -v -count=1

demo: build
	./bin/e2ee-chat demo

lint:
	gofmt -l . | tee /dev/stderr | (! read)
	go vet ./...

tidy:
	go mod tidy
	git diff --exit-code go.mod go.sum

docker:
	docker build -t e2ee-chat:local --build-arg VERSION=$(VERSION) .

clean:
	rm -rf bin dist
