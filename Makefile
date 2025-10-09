SHELL := /usr/bin/env bash
.SHELLFLAGS += -o pipefail -O extglob

GOLANGCI_LINT_VERSION := v2.4.0

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)


## Tool Binaries
GO_RUN := go run
GOLANGCI_LINT ?= $(GO_RUN) github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)


.PHONY: lint
lint: ## Run golangci-lint linter
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

.PHONY: lint-config
lint-config: ## Verify golangci-lint linter configuration
	$(GOLANGCI_LINT) config verify

##@ Run targets

run-server: ## run server
	go run cmd/casbin-traefik-forward-auth/main.go --auth-route-config-path examples/pubsub-routes-expr.yaml

##@ Test targets

.PHONY: test
test: ## run tests
	go test -v -race -count=1 ./...

.PHONY: benchmark
benchmark: ## run benchmarks
	go test -bench=. -benchmem ./...

##@ Examples targets

TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY21lL3Byb2plY3QvcHJvamVjdC5pZCI6IjEyMzQ1Njc4OTAxMiIsImF1ZCI6WyJhY21lIiwiYXBpIl0sImF6cCI6Im1pY2hhbC10ZXN0LWFvZXlkODFAc2EuYWNtZS5jbG91ZCIsImVtYWlsIjoibWljaGFsLXRlc3QtYW9leWQ4MUBzYS5hY21lLmNsb3VkIiwiZXhwIjoxNzYwMDMzNTczLCJpYXQiOjE3NjAwMjk5NzMsImlzcyI6ImFjbWUvc2VydmljZWFjY291bnQiLCJqdGkiOiJhMDM5MjNjMS01ZTk5LTQ4OGEtYmQxYS1lMjAxYWY5NTZkMTciLCJzdWIiOiI5ZTRmZGIxYy0zMzQ1LTRjMDctOThkOS03M2I5OTNjOWRkNDIifQ.7In_S9Llms9H_WuBSDLKhEMS-Pk_6U5y-lNrz-rxuU8

example-grant:
	kubectl apply -f examples/pubsub-policy.yaml

example-revoke:
	kubectl delete -f examples/pubsub-policy.yaml

example-publish:
	curl -v -H "Authorization: Bearer $(TOKEN)" -H "X-Forwarded-Method: POST" -H "X-Forwarded-Host: orders.localhost" -H "X-Forwarded-Uri: /v1alpha/publish" localhost:8080/auth

example-read:
	curl -v -H "Authorization: Bearer $(TOKEN)" -H "X-Forwarded-Method: POST" -H "X-Forwarded-Host: orders.localhost" -H "X-Forwarded-Uri: /v1alpha/subscriptions/order-updates/pull" localhost:8080/auth
	curl -v -H "Authorization: Bearer $(TOKEN)" -H "X-Forwarded-Method: POST" -H "X-Forwarded-Host: orders.localhost" -H "X-Forwarded-Uri: /v1alpha/subscriptions/order-updates/ack" localhost:8080/auth
	curl -v -H "Authorization: Bearer $(TOKEN)" -H "X-Forwarded-Method: POST" -H "X-Forwarded-Host: orders.localhost" -H "X-Forwarded-Uri: /v1alpha/subscriptions/order-updates/nack" localhost:8080/auth

example: example-grant example-publish example-read
