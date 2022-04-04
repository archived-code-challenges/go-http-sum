#!/usr/bin/make -f

.ONESHELL:
.SHELL := /usr/bin/bash

AUTHOR := "noelruault"
PROJECTNAME := $(shell basename "$$(pwd)")
PROJECTPATH := $(shell pwd)

help:
	@echo "Usage: make [options] [arguments]\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

docker-build: ## Builds the project binary inside a docker image.
	docker build --no-cache -t $(PROJECTNAME) .

docker-run: docker-build ## Builds an image and runs a docker container for this project.
	docker run -p 8000:8000 -it $(PROJECTNAME)

run: ## Starts API project in the current machine
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go run $(LDFLAGS) .

test: ## Runs the tests for this project
	go test -v ./...
