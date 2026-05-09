# Variables
APP_NAME := geoip-policyd
VERSION := $(shell git describe --tags --always --dirty)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
PREFIX := /usr/local
BIN_DIR := $(PREFIX)/sbin
SYSTEMD_DIR := /usr/lib/systemd/system
DEFAULTS_DIR := /etc/default
GOLANGCI_NEW_FROM_REV ?= HEAD

# Default target
all: build

# Build target
build:
	go build -mod=vendor -trimpath $(LDFLAGS) -o $(APP_NAME)

# Build check target
build-check:
	go build -mod=vendor ./...

# Install target
install: build
	install -d $(DESTDIR)$(BIN_DIR)
	install -m 0755 $(APP_NAME) $(DESTDIR)$(BIN_DIR)/
	install -d $(DESTDIR)$(SYSTEMD_DIR)
	install -m 0644 systemd/$(APP_NAME).service $(DESTDIR)$(SYSTEMD_DIR)/
	install -d $(DESTDIR)$(DEFAULTS_DIR)
	install -m 0644 systemd/$(APP_NAME) $(DESTDIR)$(DEFAULTS_DIR)/

# Uninstall target
uninstall:
	rm -f $(DESTDIR)$(BIN_DIR)/$(APP_NAME)
	rm -f $(DESTDIR)$(SYSTEMD_DIR)/$(APP_NAME).service
	rm -f $(DESTDIR)$(DEFAULTS_DIR)/$(APP_NAME)

# Clean target
clean:
	rm -f $(APP_NAME)

# Test targets
fix:
	go fix ./...

vet:
	go vet ./...

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not found. Install it and rerun make guardrails"; exit 1; }
	golangci-lint run --new-from-rev=$(GOLANGCI_NEW_FROM_REV) ./...

test:
	go test -v ./...

race:
	go test -race -short $$(go list ./... | grep -v /vendor/)

msan:
	go test -msan -short $$(go list ./... | grep -v /vendor/)

guardrails: fix vet lint test race build-check

# Print version
version:
	@echo $(VERSION)

.PHONY: all build build-check clean version install uninstall fix vet lint test race msan guardrails
