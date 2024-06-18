GO_TEST = go run gotest.tools/gotestsum --format pkgname

ifndef $(GOPATH)
    GOPATH=$(shell go env GOPATH)
    export GOPATH
endif

ARTIFACT_NAME = external-dns-huaweicloud-webhook

# logging
LOG_LEVEL = debug
LOG_ENVIRONMENT = production
LOG_FORMAT = auto


REGISTRY ?= localhost:5001
IMAGE_NAME ?= external-dns-huaweicloud-webhook
IMAGE_TAG ?= latest
IMAGE = $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

show: ## Show variables
	@echo "GOPATH: $(GOPATH)"
	@echo "ARTIFACT_NAME: $(ARTIFACT_NAME)"
	@echo "REGISTRY: $(REGISTRY)"
	@echo "IMAGE_NAME: $(IMAGE_NAME)"
	@echo "IMAGE_TAG: $(IMAGE_TAG)"
	@echo "IMAGE: $(IMAGE)"

##@ GO

.PHONY: clean
clean: ## Clean the build directory
	rm -rf ./dist
	rm -rf ./build
	rm -rf ./vendor

.PHONY: build
build: ## Build the binary
	CGO_ENABLED=0 go build -o build/bin/$(ARTIFACT_NAME) ./cmd/webhook

.PHONY: run
run:build ## Run the binary on local machine
	LOG_LEVEL=$(LOG_LEVEL) LOG_ENVIRONMENT=$(LOG_ENVIRONMENT) LOG_FORMAT=$(LOG_FORMAT) build/bin/external-dns-huaweicloud-webhook

##@ Docker

.PHONY: docker-build
docker-build:  ## Build the docker image
	docker build ./ -f Dockerfile -t $(IMAGE)

.PHONY: docker-push
docker-push: ## Push the docker image
	docker push $(IMAGE)
