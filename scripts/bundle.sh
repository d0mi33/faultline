#!/usr/bin/env bash
# Build an offline install bundle: every image Faultline runs, the code, and an
# installer. For hosts and clusters that can't pull from Docker Hub or PyPI.
#
#   scripts/bundle.sh                  # -> dist/faultline-bundle-<git-sha>.tar.gz
#   PLATFORM=linux/arm64 scripts/bundle.sh
#
# It does not ship a CNI: on a customer cluster, use theirs and let
# `python3 -m faultline.doctor --k8s` prove it enforces NetworkPolicy.
set -euo pipefail
cd "$(dirname "$0")/.."

PLATFORM="${PLATFORM:-linux/amd64}"
IMAGES=(faultline/proxy:dev faultline/agent:dev faultline/mock-llm:dev postgres:16-alpine busybox:1.36)
SHA="$(git rev-parse --short HEAD)$(git diff --quiet HEAD -- . ':!runs' || echo -dirty)"
NAME="faultline-bundle-${SHA}"
OUT="dist/${NAME}"

rm -rf "$OUT" && mkdir -p "$OUT/src"
docker build -q -t faultline/proxy:dev proxy >/dev/null
docker build -q -t faultline/agent:dev target-agent >/dev/null
docker build -q -t faultline/mock-llm:dev mock-llm >/dev/null
for img in postgres:16-alpine busybox:1.36; do
  docker image inspect "$img" >/dev/null 2>&1 || docker pull -q --platform "$PLATFORM" "$img"
done

# One platform only: multi-arch indexes reference blobs that aren't in the
# archive, which breaks `kind load` and some registries.
docker save --platform "$PLATFORM" -o "$OUT/images.tar" "${IMAGES[@]}"

# Tracked files plus new ones, minus anything gitignored (runs/, .env*, keys).
git ls-files -co --exclude-standard -z | grep -zv '^dist/' | xargs -0 cp --parents -t "$OUT/src"
cp scripts/bundle-install.sh "$OUT/install.sh"
printf '%s\n' "${IMAGES[@]}" > "$OUT/images.txt"
cat > "$OUT/manifest.json" <<JSON
{"name": "faultline", "version": "${SHA}", "platform": "${PLATFORM}",
 "built": "$(date -u +%Y-%m-%dT%H:%M:%SZ)", "images": $(printf '"%s",' "${IMAGES[@]}" | sed 's/,$//; s/^/[/; s/$/]/')}
JSON
(cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)

tar -C dist -czf "dist/${NAME}.tar.gz" "$NAME"
rm -rf "$OUT"
echo "dist/${NAME}.tar.gz ($(du -h "dist/${NAME}.tar.gz" | cut -f1))"
