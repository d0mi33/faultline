#!/usr/bin/env bash
# Faultline offline installer. Ships inside the bundle as install.sh.
#
#   ./install.sh                                  # docker host: load images, use docker compose
#   ./install.sh --kind faultline                 # load images into a kind cluster
#   ./install.sh --registry registry.corp:5000       # push to a private registry, rewrite manifests
#
# Then: cd src && python3 -m faultline.doctor [--k8s]
set -euo pipefail
cd "$(dirname "$0")"

KIND="" REGISTRY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kind) KIND="$2"; shift 2 ;;
    --registry) REGISTRY="${2%/}"; shift 2 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
done

echo "verifying checksums"
sha256sum --quiet -c SHA256SUMS

echo "loading images"
docker load -q -i images.tar

if [[ -n "$KIND" ]]; then
  # `kind load` imports every platform and trips over single-platform archives
  # from containerd-backed Docker, so import into each node for one platform.
  PLATFORM="$(sed -nE 's/.*"platform": "([^"]+)".*/\1/p' manifest.json)"
  for node in $(kind get nodes --name "$KIND"); do
    docker exec -i "$node" ctr -n k8s.io images import --platform "$PLATFORM" --snapshotter=overlayfs - < images.tar >/dev/null
    echo "  loaded into $node"
  done
fi

if [[ -n "$REGISTRY" ]]; then
  while read -r img; do
    docker tag "$img" "$REGISTRY/$img"
    docker push -q "$REGISTRY/$img"
  done < images.txt
  # Point every manifest at the private registry; nothing pulls from Docker Hub.
  sed -i -E "s#image: (faultline/|postgres:|busybox:)#image: $REGISTRY/\1#" src/k8s/base/system.yaml src/k8s/run-template/run.yaml
  echo "export FAULTLINE_PROBE_IMAGE=$REGISTRY/busybox:1.36   # for doctor and verify-isolation"
fi

echo "installed. next: cd src && python3 -m faultline.doctor $([[ -n "$KIND$REGISTRY" ]] && echo --k8s)"
