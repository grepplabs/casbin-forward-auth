#!/usr/bin/env bash

set -euo pipefail

KIND_K8S_VERSION="${1:-1.32}"
CLUSTER_NAME="${2:-chainsaw-tests}"
CREATE_CLUSTER="${3:-true}"

CHAINSAW=${CHAINSAW:-chainsaw}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="${ROOT_DIR}"/tmp
export KUBECONFIG="${TEMP_DIR}"/kubeconfig-${CLUSTER_NAME}-${KIND_K8S_VERSION}

mkdir -p "${ROOT_DIR}"/tmp
if [ "$CREATE_CLUSTER" == "true" ]; then
  # configure local credentials
  KIND_CONFIG=${TEMP_DIR}/kubernetes-${KIND_K8S_VERSION}.yaml
  USER_HOME="${HOME}" yq 'with(.nodes[].extraMounts; . += [{"containerPath": "/var/lib/kubelet/config.json", "hostPath": strenv(USER_HOME) + "/.docker/config.json"}])' \
    < "${ROOT_DIR}/kubernetes-${KIND_K8S_VERSION}.yaml" > ${KIND_CONFIG}

  # create cluster
  kind create cluster --name $CLUSTER_NAME --config "${ROOT_DIR}/kubernetes-${KIND_K8S_VERSION}.yaml" --kubeconfig "${KUBECONFIG}" || exit 1
  trap "kind delete cluster --name ${CLUSTER_NAME}" EXIT
fi

kind load docker-image --name ${CLUSTER_NAME} local/casbin-traefik-forward-auth:latest

kubectl kustomize ${ROOT_DIR}/setup/crds --enable-helm | kubectl apply --server-side=true -f -
kubectl kustomize ${ROOT_DIR}/setup/manifests --enable-helm | kubectl apply --server-side=true -f -

${CHAINSAW} version
