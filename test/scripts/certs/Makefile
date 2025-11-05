SHELL := /bin/bash
.SHELLFLAGS += -o pipefail -O extglob
.DEFAULT_GOAL := help

ROOT_DIR  := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CERT_DIR_CONFIG := $(ROOT_DIR)/config
CERT_DIR_OUTPUT := $(ROOT_DIR)/output

.PHONY: help
help: ## display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)


.PHONY: clean
clean: ## Clean up all generated SSL certificates
	rm -f $(CERT_DIR_OUTPUT)/*.pem $(CERT_DIR_OUTPUT)/*.csr

.PHONY: create
create: ## Create or regenerate SSL certificates for NATS server and clients
	mkdir -p $(CERT_DIR_OUTPUT)

	cfssl genkey -initca $(CERT_DIR_CONFIG)/csr-root-ca.json | cfssljson -bare $(CERT_DIR_OUTPUT)/ca

	cfssl gencert -ca=$(CERT_DIR_OUTPUT)/ca.pem -ca-key=$(CERT_DIR_OUTPUT)/ca-key.pem -config=$(CERT_DIR_CONFIG)/ca-config.json \
	  -profile=casbin-auth-server $(CERT_DIR_CONFIG)/csr-casbin-auth-server.json | cfssljson -bare $(CERT_DIR_OUTPUT)/casbin-auth-server

	cfssl gencert -ca=$(CERT_DIR_OUTPUT)/ca.pem -ca-key=$(CERT_DIR_OUTPUT)/ca-key.pem -config=$(CERT_DIR_CONFIG)/ca-config.json \
	  -profile=casbin-auth-client $(CERT_DIR_CONFIG)/csr-casbin-auth-client.json | cfssljson -bare $(CERT_DIR_OUTPUT)/casbin-auth-client
