#!/usr/bin/env bash
# Create a local kind cluster and load the Faultline images into it.
# Requires: docker, kind, kubectl. Installs Calico as the CNI so NetworkPolicy is enforced.
set -euo pipefail
cd "$(dirname "$0")/.."

for bin in kind kubectl docker; do
  command -v "$bin" >/dev/null || { echo "missing: $bin  (see https://kind.sigs.k8s.io/docs/user/quick-start/)"; exit 1; }
done

CALICO_VERSION=v3.28.2
if ! kind get clusters | grep -qx faultline; then
  kind create cluster --config k8s/kind-config.yaml
  kubectl apply -f "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
fi
kubectl -n kube-system rollout status ds/calico-node --timeout=300s
kubectl wait --for=condition=Ready nodes --all --timeout=300s

docker build -t faultline/proxy:dev    proxy
docker build -t faultline/agent:dev    target-agent
docker build -t faultline/mock-llm:dev mock-llm
kind load docker-image --name faultline faultline/proxy:dev faultline/agent:dev faultline/mock-llm:dev

kubectl apply -f k8s/base/system.yaml
kubectl -n faultline-system rollout status deploy/mock-llm --timeout=120s
echo "cluster ready: python -m faultline.run --backend k8s --scenario prompt_injection"
