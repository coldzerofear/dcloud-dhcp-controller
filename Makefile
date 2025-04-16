GOOS ?= linux

# Image URL to use all building/pushing image targets
IMG_PREFIX ?= registry.tydic.com/dcloud
TAG ?= latest
IMG ?= ${IMG_PREFIX}/dcloud-dhcp-controller:$(TAG)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: fmt vet ## Run tests.
	CGO_ENABLED=0 GOOS=$(GOOS) go test ./... -coverprofile cover.out

##@ Build

.PHONY: build
build: fmt vet ## Build binary.
	CGO_ENABLED=1 GOOS=${TARGETOS:-linux} \
	CGO_CFLAGS_ALLOW="-mrtm|-Wp,-D_FORTIFY_SOURCE.*|-fstack-protector.*" \
 	CGO_LDFLAGS_ALLOW="-Wl,--(?:no-)?whole-archive|-Wl,-z,now|-Wl,-z,relro" \
    go build -ldflags="-extldflags=-Wl,--no-as-needed" -o dhcp-controller .

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image.
	$(CONTAINER_TOOL) build -f ./Dockerfile -t "${IMG_PREFIX}/dcloud-dhcp-controller:$(TAG)" .

.PHONY: docker-push
docker-push: ## Push docker image.
	$(CONTAINER_TOOL) push ${IMG_PREFIX}/dcloud-dhcp-controller:$(TAG)

##@ Release
.PHONY: publish # Push the image to the remote registry
publish:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--output "type=image,push=true" \
		--file ./Dockerfile.cross \
		--tag $(IMG) \
		.
