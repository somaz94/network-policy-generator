#!/usr/bin/env bash
# Runs the README demo for real on a throwaway kind cluster, with
# network-policy-generator installed from helm/network-policy-generator and its published
# image, and saves each command's output under examples/demo/captured/.
# Usage: examples/demo/capture.sh   (needs kind, kubectl and helm; pulls the image)
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
ROOT_DIR="$(cd "${DEMO_DIR}/../.." && pwd)"
OUT="${DEMO_DIR}/captured"
CLUSTER="npg-demo"

for tool in kind kubectl helm; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "${tool} not found" >&2; exit 1; }
done
if kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
    echo "kind cluster ${CLUSTER} already exists; delete it first" >&2
    exit 1
fi

WORK="$(mktemp -d)"
# kind would otherwise switch the current context of the user's own kubeconfig.
export KUBECONFIG="${WORK}/kubeconfig"
cleanup() {
    kind delete cluster --name "${CLUSTER}" --kubeconfig "${KUBECONFIG}" >/dev/null 2>&1 || true
    rm -rf "${WORK:?}"
}
trap cleanup EXIT

kind create cluster --name "${CLUSTER}" --kubeconfig "${KUBECONFIG}" --wait 60s
helm install network-policy-generator "${ROOT_DIR}/helm/network-policy-generator" --wait --timeout 3m

cd "${DEMO_DIR}"
kubectl create namespace shop

rm -rf "${OUT}"
mkdir -p "${OUT}"
kubectl get networkpolicy -n shop > "${OUT}/01-kubectl" 2>&1
kubectl apply -f generator.yaml > "${OUT}/02-kubectl" 2>&1
# Off screen: wait for the generated policy so the next capture shows the result.
for _ in $(seq 1 60); do
    [ -n "$(kubectl get networkpolicy -n shop -o name 2>/dev/null)" ] && break
    sleep 1
done
kubectl get networkpolicygenerator -n shop > "${OUT}/03-kubectl" 2>&1
kubectl get networkpolicy -n shop > "${OUT}/04-kubectl" 2>&1
kubectl describe networkpolicy -n shop > "${OUT}/05-kubectl" 2>&1

echo "captured into ${OUT}"
