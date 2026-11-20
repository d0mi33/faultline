#!/usr/bin/env bash
# Prove the sandbox is sealed: from inside a run namespace, the agent pod must
# NOT reach the internet or the mock LLM directly, but MUST reach the proxy.
set -uo pipefail
NS="${1:?usage: verify-isolation.sh <run-namespace>}"
probe() {  # name, command, expect(0=reachable,1=blocked)
  kubectl -n "$NS" run "probe-$RANDOM" --rm -i --restart=Never --quiet \
    --labels=app=agent --image="${FAULTLINE_PROBE_IMAGE:-busybox:1.36}" -- sh -c "$2" >/dev/null 2>&1
  got=$?; [[ $got -eq 0 ]] && got=0 || got=1
  [[ $got -eq $3 ]] && echo "PASS  $1" || echo "FAIL  $1"
}
probe "agent -> proxy:8080 allowed"        "nc -z -w3 proxy 8080"                                         0
probe "agent -> postgres:5432 allowed"     "nc -z -w3 postgres 5432"                                      0
probe "agent -> internet blocked"          "nc -z -w3 1.1.1.1 443"                                        1
probe "agent -> mock-llm direct blocked"   "nc -z -w3 mock-llm.faultline-system.svc.cluster.local 8000"    1
probe "agent -> cloud metadata blocked"    "nc -z -w3 169.254.169.254 80"                                 1
