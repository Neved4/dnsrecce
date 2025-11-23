.POSIX:

.PHONY: all fmt vet test tidy build run go-run clean

all: fmt vet test

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	GOCACHE="$(PWD)/.gocache" go test ./...

tidy:
	go mod tidy

build:
	GOCACHE="$(PWD)/.gocache" go build -o bin/dnsrecce ./cmd/dnsrecce

run:
	GOCACHE="$(PWD)/.gocache" go run ./cmd/dnsrecce

go-run: run

clean:
	rm -rf bin "$(PWD)/.gocache" dnsrecce
