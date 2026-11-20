"""
faultline.doctor: preflight checks before running on a new host or cluster.

  python -m faultline.doctor                          # docker / compose host
  python -m faultline.doctor --env-file .env.mymodel  # + is the model gateway reachable from a container
  python -m faultline.doctor --k8s                    # + does the cluster actually enforce NetworkPolicy

Each check proves the behaviour instead of reading config. The reason: on kind's
default CNI, NetworkPolicies are accepted by the API server and silently ignored.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid

PROBE_IMAGE = os.environ.get("FAULTLINE_PROBE_IMAGE", "busybox:1.36")  # set by install.sh --registry
IMAGES = ["faultline/proxy:dev", "faultline/agent:dev", "faultline/mock-llm:dev", "postgres:16-alpine", PROBE_IMAGE]
results: list[tuple[str, str, str]] = []


def check(status: str, name: str, detail: str = "") -> None:
    results.append((status, name, detail))
    print(f"{status:<5} {name}{'  ' + detail if detail else ''}", flush=True)


def run(*args: str, env: dict | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env={**os.environ, **(env or {})})
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(args, 127, "", str(e))


# --------------------------------------------------------------------------- #
# docker / compose host
# --------------------------------------------------------------------------- #

def docker_checks() -> bool:
    r = run("docker", "version", "--format", "{{.Server.Version}}")
    if r.returncode:
        check("FAIL", "docker daemon reachable", r.stderr.strip()[:120])
        return False
    check("PASS", "docker daemon reachable", f"server {r.stdout.strip()}")
    r = run("docker", "compose", "version", "--short")
    check("PASS" if r.returncode == 0 else "FAIL", "docker compose v2", r.stdout.strip() or r.stderr.strip()[:120])

    missing = [i for i in IMAGES if run("docker", "image", "inspect", i).returncode]
    check("WARN" if missing else "PASS", "images present locally",
          f"missing: {', '.join(missing)} (built or pulled on first run; offline hosts need the bundle)" if missing else "")

    # An internal network must have no route out. Control first: if containers
    # can't reach the internet at all, a "blocked" result proves nothing.
    probe = ["nc", "-z", "-w3", "1.1.1.1", "443"]
    control = run("docker", "run", "--rm", PROBE_IMAGE, *probe)
    net = f"faultline-doctor-{uuid.uuid4().hex[:6]}"
    run("docker", "network", "create", "--internal", net)
    try:
        sealed = run("docker", "run", "--rm", "--network", net, PROBE_IMAGE, *probe)
    finally:
        run("docker", "network", "rm", net)
    if sealed.returncode == 0:
        check("FAIL", "internal network has no egress", "a container on an --internal network reached 1.1.1.1:443")
    elif control.returncode:
        check("WARN", "internal network has no egress", "inconclusive: containers can't reach the internet on a normal network either")
    else:
        check("PASS", "internal network has no egress", "reachable on a normal network, blocked on --internal")
    return True


def read_env_file(path: str) -> dict[str, str]:
    env = {}
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip("'\"")
    return env


# Runs inside a container, the way the proxy reaches the gateway. The key comes
# from the container's environment, never from argv.
MODELS_PROBE = """
import os, sys, urllib.request, urllib.error
req = urllib.request.Request(os.environ["OPENAI_BASE_URL"].rstrip("/") + "/models",
                             headers={"Authorization": "Bearer " + os.environ.get("OPENAI_API_KEY", "")})
try:
    with urllib.request.urlopen(req, timeout=15) as r:
        print(r.status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:
    print("ERR", type(e).__name__, e)
"""


def llm_check(env_file: str) -> None:
    env = read_env_file(env_file)
    base = env.get("OPENAI_BASE_URL")
    if not base:
        check("FAIL", "model gateway reachable", f"{env_file} has no OPENAI_BASE_URL")
        return
    r = run("docker", "run", "--rm", "--add-host", "host.docker.internal:host-gateway",
            "-e", "OPENAI_BASE_URL", "-e", "OPENAI_API_KEY", "--entrypoint", "python",
            "faultline/agent:dev", "-c", MODELS_PROBE,
            env={"OPENAI_BASE_URL": base, "OPENAI_API_KEY": env.get("OPENAI_API_KEY", "")})
    out = (r.stdout or r.stderr).strip()
    if out == "200":
        check("PASS", "model gateway reachable", f"{base} answered /models")
    elif out in ("401", "403"):
        check("FAIL", "model gateway reachable", f"{base} rejected the key (HTTP {out})")
    else:
        check("FAIL", "model gateway reachable", f"{base}: {out[:120]}")
    model = env.get("MODEL")
    if model and out == "200":
        check("INFO", "model under test", model)


# --------------------------------------------------------------------------- #
# Kubernetes
# --------------------------------------------------------------------------- #

DENY_EGRESS = {
    "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
    "metadata": {"name": "deny-egress"},
    "spec": {"podSelector": {"matchLabels": {"role": "probe"}}, "policyTypes": ["Egress"]},
}


def k8s_probe(ns: str, ip: str) -> bool:
    r = run("kubectl", "-n", ns, "run", f"probe-{uuid.uuid4().hex[:5]}", "--rm", "-i", "--restart=Never", "--quiet",
            "--labels=role=probe", f"--image={PROBE_IMAGE}", "--image-pull-policy=IfNotPresent",
            "--", "nc", "-z", "-w3", ip, "8080", timeout=90)
    return r.returncode == 0


def k8s_checks() -> None:
    r = run("kubectl", "get", "nodes", "-o", "json")
    if r.returncode:
        check("FAIL", "cluster reachable", r.stderr.strip()[:120])
        return
    nodes = json.loads(r.stdout)["items"]
    check("PASS", "cluster reachable", f"{len(nodes)} nodes, context {run('kubectl', 'config', 'current-context').stdout.strip()}")

    pods = run("kubectl", "-n", "kube-system", "get", "pods", "-o", "name").stdout
    cni = next((c for c in ("calico", "cilium", "antrea", "weave", "kindnet", "flannel") if c in pods), "unknown")
    check("INFO", "CNI", cni)

    if run("kubectl", "get", "ns", "faultline-system").returncode:
        check("WARN", "faultline-system namespace", "missing: run scripts/cluster-up.sh (or apply k8s/base/system.yaml)")
    else:
        check("PASS", "faultline-system namespace")

    # Pod-to-pod by IP, so it works on clusters with no internet and no DNS assumptions.
    ns = f"faultline-doctor-{uuid.uuid4().hex[:6]}"
    run("kubectl", "create", "namespace", ns)
    try:
        run("kubectl", "-n", ns, "run", "target", f"--image={PROBE_IMAGE}", "--image-pull-policy=IfNotPresent",
            "--", "httpd", "-f", "-p", "8080")
        if run("kubectl", "-n", ns, "wait", "--for=condition=Ready", "pod/target", "--timeout=90s").returncode:
            check("FAIL", "NetworkPolicy enforced", f"probe pod never became ready (can the cluster pull {PROBE_IMAGE}?)")
            return
        ip = run("kubectl", "-n", ns, "get", "pod", "target", "-o", "jsonpath={.status.podIP}").stdout.strip()
        if not k8s_probe(ns, ip):
            check("WARN", "NetworkPolicy enforced", "inconclusive: pods can't reach each other even without a policy")
            return
        subprocess.run(["kubectl", "-n", ns, "apply", "-f", "-"], input=json.dumps(DENY_EGRESS),
                       capture_output=True, text=True)
        blocked = False
        for _ in range(4):  # the CNI programs rules asynchronously
            time.sleep(2)
            if not k8s_probe(ns, ip):
                blocked = True
                break
        if blocked:
            check("PASS", "NetworkPolicy enforced", "pod-to-pod allowed without a policy, blocked with deny-egress")
        else:
            check("FAIL", "NetworkPolicy enforced",
                  f"deny-egress was accepted but traffic still flows: the CNI ({cni}) is ignoring NetworkPolicy")
    finally:
        run("kubectl", "delete", "namespace", ns, "--wait=false")


def main() -> None:
    ap = argparse.ArgumentParser(prog="faultline.doctor")
    ap.add_argument("--env-file", default="", help="also check the model gateway in this env file")
    ap.add_argument("--k8s", action="store_true", help="also check the current kubectl cluster")
    args = ap.parse_args()

    if docker_checks() and args.env_file:
        llm_check(args.env_file)
    if args.k8s:
        k8s_checks()
    failed = [r for r in results if r[0] == "FAIL"]
    print(f"\n{len(failed)} failed, {sum(r[0] == 'WARN' for r in results)} warnings, {len(results)} checks")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
