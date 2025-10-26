SHELL := /usr/bin/env bash
.SHELLFLAGS += -o pipefail -O extglob
.DEFAULT_GOAL := help

ROOT_DIR       = $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

GOLANGCI_LINT_VERSION := v2.4.0
CHAINSAW_VERSION := v0.2.13

LOCAL_IMAGE := local/casbin-traefik-forward-auth:latest
LOCAL_CLUSTER_ROOT_DIR ?= $(ROOT_DIR)/test/scripts/local/local-cluster
LOCAL_CLUSTER_NAME ?= casbin-traefik
LOCAL_KIND_CONFIG ?= $(ROOT_DIR)/kind-config-$(LOCAL_CLUSTER_NAME).yaml
LOCAL_KUBECONFIG ?= $(ROOT_DIR)/kubeconfig-$(LOCAL_CLUSTER_NAME)

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)


## Tool Binaries
GO_RUN := go run
GOLANGCI_LINT ?= $(GO_RUN) github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
export CHAINSAW ?= $(GO_RUN) github.com/kyverno/chainsaw@$(CHAINSAW_VERSION)

.PHONY: lint
lint: ## Run golangci-lint linter
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

.PHONY: lint-config
lint-config: ## Verify golangci-lint linter configuration
	$(GOLANGCI_LINT) config verify


##@ Development

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: tidy
tidy: ## Run go mod tidy.
	go mod tidy

##@ Build

.PHONY: build
build: ## Build binary.
	go build -gcflags "all=-N -l" -o ./casbin-traefik-forward-auth ./cmd/casbin-traefik-forward-auth

##@ Docker

.PHONY: docker-build
docker-build: ## Build docker image.
	docker build -t ${LOCAL_IMAGE} .

##@ Run targets

run-server: ## run server
	go run cmd/casbin-traefik-forward-auth/main.go --auth-route-config-path=examples/pubsub-routes-expr.yaml

##@ Local cluster

.PHONY: local-cluster-create
local-cluster-create:  ## create local kind cluster
	USER_HOME="$(HOME)" yq 'with(.nodes[].extraMounts; . += [{"containerPath": "/var/lib/kubelet/config.json", "hostPath": strenv(USER_HOME) + "/.docker/config.json"}])' \
		< "$(LOCAL_CLUSTER_ROOT_DIR)/kind-config.yaml" > "$(LOCAL_KIND_CONFIG)"
	kind create cluster --name "$(LOCAL_CLUSTER_NAME)" --config "$(LOCAL_KIND_CONFIG)" --kubeconfig "$(LOCAL_KUBECONFIG)"

.PHONY: local-cluster-delete
local-cluster-delete:  ## delete local kind cluster
	rm -f $(LOCAL_KIND_CONFIG)
	rm -f $(LOCAL_KUBECONFIG)
	kind delete cluster --name $(LOCAL_CLUSTER_NAME)

.PHONY: local-apply
local-apply: export KUBECONFIG=$(LOCAL_KUBECONFIG)
local-apply:
	kind load docker-image --name ${LOCAL_CLUSTER_NAME} local/casbin-traefik-forward-auth:latest
	kubectl kustomize $(LOCAL_CLUSTER_ROOT_DIR)/../traefik-crds --enable-helm | kubectl apply --server-side=true -f -
	kubectl kustomize $(LOCAL_CLUSTER_ROOT_DIR) --enable-helm | kubectl apply --server-side=true -f -
	- kubectl delete pod -n casbin-auth --all

.PHONY: local-deploy
local-deploy: docker-build local-apply ## deploy to local kind cluster

.PHONY: local-init
local-init: local-cluster-create local-deploy ## init local cluster

##@ Test targets

.PHONY: test
test: ## run tests
	go test -v -race -count=1 ./...

.PHONY: benchmark
benchmark: ## run benchmarks
	go test -bench=. -benchmem ./...

##@ Examples targets

TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY21lL3Byb2plY3QvcHJvamVjdC5pZCI6IjEyMzQ1Njc4OTAxMiIsImF1ZCI6WyJhY21lIiwiYXBpIl0sImF6cCI6Im1pY2hhbC10ZXN0LWFvZXlkODFAc2EuYWNtZS5jbG91ZCIsImVtYWlsIjoibWljaGFsLXRlc3QtYW9leWQ4MUBzYS5hY21lLmNsb3VkIiwiZXhwIjoxNzYwMDMzNTczLCJpYXQiOjE3NjAwMjk5NzMsImlzcyI6ImFjbWUvc2VydmljZWFjY291bnQiLCJqdGkiOiJhMDM5MjNjMS01ZTk5LTQ4OGEtYmQxYS1lMjAxYWY5NTZkMTciLCJzdWIiOiI5ZTRmZGIxYy0zMzQ1LTRjMDctOThkOS03M2I5OTNjOWRkNDIifQ.7In_S9Llms9H_WuBSDLKhEMS-Pk_6U5y-lNrz-rxuU8

example-grant: ## grant access
	kubectl apply -f examples/pubsub-policy.yaml

example-revoke: ## revoke access
	kubectl delete -f examples/pubsub-policy.yaml

example-publish: ## publish data
	curl -v -H "Authorization: Bearer $(TOKEN)" -H "X-Forwarded-Method: POST" -H "X-Forwarded-Host: orders.localhost" -H "X-Forwarded-Uri: /v1alpha/publish" localhost:8080/v1/auth

example-read: ## read data
	curl -v -H "Authorization: Bearer $(TOKEN)" -H "X-Forwarded-Method: POST" -H "X-Forwarded-Host: orders.localhost" -H "X-Forwarded-Uri: /v1alpha/subscriptions/order-updates/pull" localhost:8080/v1/auth
	curl -v -H "Authorization: Bearer $(TOKEN)" -H "X-Forwarded-Method: POST" -H "X-Forwarded-Host: orders.localhost" -H "X-Forwarded-Uri: /v1alpha/subscriptions/order-updates/ack" localhost:8080/v1/auth
	curl -v -H "Authorization: Bearer $(TOKEN)" -H "X-Forwarded-Method: POST" -H "X-Forwarded-Host: orders.localhost" -H "X-Forwarded-Uri: /v1alpha/subscriptions/order-updates/nack" localhost:8080/v1/auth

example-all: example-grant example-publish example-read example-revoke

##@ Traefik test targets

TESTDATA_DIR := test/scripts/chainsaw/testdata/

traefik-grant: export KUBECONFIG=$(LOCAL_KUBECONFIG)
traefik-grant: ## grant access
	kubectl apply -f $(TESTDATA_DIR)/echo-pubsub-policy.yaml

traefik-revoke: export KUBECONFIG=$(LOCAL_KUBECONFIG)
traefik-revoke: ## revoke access
	kubectl delete -f $(TESTDATA_DIR)/echo-pubsub-policy.yaml

traefik-publish: ## publish data
	curl -v -H "Authorization: Bearer $(TOKEN)" -H 'Host: echo.local' -X POST http://localhost:30080/v1alpha/publish

traefik-read: ## read data
	curl -v -H "Authorization: Bearer $(TOKEN)" -H 'Host: echo.local' -X POST http://localhost:30080/v1alpha/subscriptions/order-updates/pull
	curl -v -H "Authorization: Bearer $(TOKEN)" -H 'Host: echo.local' -X POST http://localhost:30080/v1alpha/subscriptions/order-updates/ack
	curl -v -H "Authorization: Bearer $(TOKEN)" -H 'Host: echo.local' -X POST http://localhost:30080/v1alpha/subscriptions/order-updates/nack

traefik-all: traefik-grant traefik-publish traefik-read traefik-revoke

##@ E2E tests

.PHONY: chainsaw-test
chainsaw-test: docker-build ## Run the e2e tests using chainsaw
	@test/scripts/chainsaw/chainsaw-test.sh "1.32"
