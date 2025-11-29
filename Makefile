#!/bin/make

GOROOT:=$(shell PATH="/pkg/main/dev-lang.go.dev/bin:$$PATH" go env GOROOT)
GO_TAG:=$(shell /bin/sh -c 'eval `$(GOROOT)/bin/go tool dist env`; echo "$${GOOS}_$${GOARCH}"')
GIT_TAG:=$(shell git rev-parse --short HEAD)
GOPATH:=$(shell $(GOROOT)/bin/go env GOPATH)

all: build

.PHONY: build test deps

build:
	$(GOPATH)/bin/goimports -w -l .
	$(GOROOT)/bin/go build ./...

test:
	$(GOROOT)/bin/go test -v ./...

deps:
	$(GOROOT)/bin/go get -v -t .
