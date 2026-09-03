# Load .env if it exists (for CF_API_TOKEN, AIO_EMAIL, etc.)
-include .env
export

.PHONY: build build-server build-client build-token run-server run-client test test-race clean

BINARY_SERVER = build/mabo-tunnel-server
BINARY_CLIENT = build/mabo-tunnel-client
BINARY_TOKEN  = build/mabo-tunnel-token

# Version stamped into both binaries. Defaults to the current git description.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
VERSION_PKG = github.com/maborak/mabo-tunnel/internal/version
LDFLAGS = -X $(VERSION_PKG).Version=$(VERSION)

build: build-server build-client build-token

build-server:
	@mkdir -p build
	go build -ldflags="$(LDFLAGS)" -o $(BINARY_SERVER) ./cmd/server

build-client:
	@mkdir -p build
	go build -ldflags="$(LDFLAGS)" -o $(BINARY_CLIENT) ./cmd/client

build-token:
	@mkdir -p build
	go build -ldflags="$(LDFLAGS)" -o $(BINARY_TOKEN) ./cmd/token

# Run against a REMOTE server. Set MABO_TUNNEL_DOMAIN / MABO_TUNNEL_SERVER in .env
# (gitignored) — these targets deliberately carry no real hostname.
run-server: build-server
	./$(BINARY_SERVER) --domain=$(MABO_TUNNEL_DOMAIN) --addr=:8080

run-client: build-client
	./$(BINARY_CLIENT) --server=$(MABO_TUNNEL_SERVER) --token=$(MABO_TUNNEL_TOKEN) --port=3000

run-server-local: build-server
	./$(BINARY_SERVER) --domain=localhost --addr=:8080

run-client-local: build-client
	./$(BINARY_CLIENT) --server=ws://localhost:8080 --token=$(MABO_TUNNEL_TOKEN) --port=3000

test:
	go test ./...

test-race:
	go test -race ./...

clean:
	rm -rf build/

# AIO release build — produces a self-contained server binary for deployment.
# Operator credentials (DNS API token, user database) are embedded encrypted
# (AES-256-GCM) so no config files or env vars are needed on the host. The
# encryption is obfuscation, not a secret store: the key ships in the same
# binary, so treat the token as exposed on any host that holds the binary.
#
# Usage:
#   make build-aio AIO_EMAIL=admin@example.com CF_API_TOKEN=xxx
#
# Set AIO_DOMAIN / AIO_EMAIL / CF_API_TOKEN in .env (gitignored) so you do not
# have to pass them every time. The tracked defaults are placeholders.
AIO_DOMAIN    ?= tunnel.example.com
AIO_EMAIL     ?= $(MABO_TUNNEL_AIO_EMAIL)
AIO_BIND      ?= $(or $(BIND_IP),0.0.0.0)
AIO_CERT_PATH ?= data/certs
AIO_USERS     ?= data/users.txt
AIO_DNS_PROVIDER ?= cloudflare
AIO_DNS_SECRET   ?= $(MABO_TUNNEL_AIO_DNS_SECRET)

HOST_GOOS     := $(shell go env GOOS)
HOST_GOARCH   := $(shell go env GOARCH)
AIO_GOOS      ?= $(HOST_GOOS)
AIO_GOARCH    ?= $(HOST_GOARCH)

# Output name for build-aio. A native build keeps the plain path, so anything
# referencing build/mabo-tunnel-server still works. A cross-compiled build gets a
# platform suffix, because a file named "mabo-tunnel-server" that is actually a
# Linux ELF is a trap.
AIO_EXT := $(if $(filter windows,$(AIO_GOOS)),.exe,)
ifeq ($(AIO_GOOS)/$(AIO_GOARCH),$(HOST_GOOS)/$(HOST_GOARCH))
AIO_OUT := $(BINARY_SERVER)$(AIO_EXT)
else
AIO_OUT := build/mabo-tunnel-server-$(AIO_GOOS)-$(AIO_GOARCH)$(AIO_EXT)
endif

# Internal: build one release binary for a given OS/ARCH/OUTPUT.
# Usage: $(call aio_build,OS,ARCH,OUTPUT)
define aio_build
	@echo ""
	@echo "==> Building $(3) ($(1)/$(2))..."
	@echo "    Embedding encrypted config..."
	@go run ./cmd/embed-secrets \
	  --domain=$(AIO_DOMAIN) --aio-email=$(AIO_EMAIL) --aio-bind=$(AIO_BIND) \
	  --aio-cert-path=$(AIO_CERT_PATH) --aio-cf-token=$(CF_API_TOKEN) \
	  --aio-dns-provider=$(AIO_DNS_PROVIDER) --aio-dns-secret="$(AIO_DNS_SECRET)" \
	  --users-file=$(AIO_USERS) --output=cmd/server/embedded.go
	GOOS=$(1) GOARCH=$(2) go build -ldflags="-w -s $(LDFLAGS)" -o $(3) ./cmd/server
	@rm -f cmd/server/embedded.go
	@echo "    Done: $(3)"
endef

# Build AIO for one platform: the host by default, or AIO_GOOS/AIO_GOARCH.
build-aio:
	@mkdir -p build
	$(call aio_build,$(AIO_GOOS),$(AIO_GOARCH),$(AIO_OUT))
	@echo ""
	@echo "==> Built AIO binary: $(AIO_OUT)"

# Build AIO for every supported platform:
# linux/{amd64,arm64}, darwin/{amd64,arm64}, windows/amd64.
build-aio-all:
	@mkdir -p build
	$(call aio_build,linux,amd64,build/mabo-tunnel-server-linux-amd64)
	$(call aio_build,linux,arm64,build/mabo-tunnel-server-linux-arm64)
	$(call aio_build,darwin,amd64,build/mabo-tunnel-server-darwin-amd64)
	$(call aio_build,darwin,arm64,build/mabo-tunnel-server-darwin-arm64)
	$(call aio_build,windows,amd64,build/mabo-tunnel-server-windows-amd64.exe)
	@echo ""
	@echo "==> Built all AIO binaries:"
	@ls -lh build/mabo-tunnel-server-*

# AIO build without symbol stripping (for dev/testing)
build-aio-dev:
	@mkdir -p build
	@go run ./cmd/embed-secrets \
	  --domain=$(AIO_DOMAIN) \
	  --aio-email=$(AIO_EMAIL) \
	  --aio-bind=$(AIO_BIND) \
	  --aio-cert-path=$(AIO_CERT_PATH) \
	  --aio-cf-token=$(CF_API_TOKEN) \
	  --aio-dns-provider=$(AIO_DNS_PROVIDER) --aio-dns-secret="$(AIO_DNS_SECRET)" \
	  --users-file=$(AIO_USERS) \
	  --output=cmd/server/embedded.go
	@go build -o $(BINARY_SERVER) ./cmd/server
	@rm -f cmd/server/embedded.go
	@echo "Built AIO binary (dev): $(BINARY_SERVER)"

# Cross-compilation
build-all:
	@mkdir -p build
	GOOS=linux GOARCH=amd64 go build -o build/mabo-tunnel-server-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=amd64 go build -o build/mabo-tunnel-client-linux-amd64 ./cmd/client
	GOOS=linux GOARCH=arm64 go build -o build/mabo-tunnel-server-linux-arm64 ./cmd/server
	GOOS=linux GOARCH=arm64 go build -o build/mabo-tunnel-client-linux-arm64 ./cmd/client
	GOOS=darwin GOARCH=amd64 go build -o build/mabo-tunnel-server-darwin-amd64 ./cmd/server
	GOOS=darwin GOARCH=amd64 go build -o build/mabo-tunnel-client-darwin-amd64 ./cmd/client
	GOOS=darwin GOARCH=arm64 go build -o build/mabo-tunnel-server-darwin-arm64 ./cmd/server
	GOOS=darwin GOARCH=arm64 go build -o build/mabo-tunnel-client-darwin-arm64 ./cmd/client
