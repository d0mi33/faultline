"""
faultline: run a fault scenario against the target agent in an isolated sandbox.

  python -m faultline.run --scenario prompt_injection            # docker compose
  python -m faultline.run --scenario rate_limit --backend k8s     # one namespace per run
  python -m faultline.run --all                                   # every scenario, summary table
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from faultline.score import aggregate, score, summary_markdown

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ""  # optional compose env file, e.g. .env.nemotron for a real model
SCENARIOS = sorted(p.stem for p in (ROOT / "proxy/faults").glob("*.yaml"))

# What the agent's DB role can actually read, per column. Feeds `faultline.map`.
AGENT_DB_ROLE = "agent"
GRANTS_SQL = (
    "SELECT table_name, column_name, "
    f"has_column_privilege('{AGENT_DB_ROLE}', format('%I.%I', table_schema, table_name), column_name, 'SELECT') "
    "FROM information_schema.columns WHERE table_schema = 'public' ORDER BY table_name, ordinal_position"
)
PSQL = ("psql", "-U", "postgres", "-d", "shop", "-At", "-F", "\t", "-c", GRANTS_SQL)


def sh(*args: str, env: dict | None = None, check: bool = True, capture: bool = False) -> str:
    print("+", " ".join(args), file=sys.stderr)
    res = subprocess.run(args, cwd=ROOT, env={**os.environ, **(env or {})}, stderr=subprocess.DEVNULL if capture else None,
                         check=check, text=True, stdout=subprocess.PIPE if capture else None)
    return res.stdout if capture else ""


# --------------------------------------------------------------------------- #
# docker compose backend
# --------------------------------------------------------------------------- #

def run_compose(run_id: str, scenario: str, run_dir: Path) -> None:
    env = {"RUN_ID": run_id, "SCENARIO": scenario}
    dc = ["docker", "compose", *(["--env-file", ENV_FILE] if ENV_FILE else [])]
    try:
        sh(*dc, "up", "-d", "--build", "--wait", "postgres", "proxy", "mock-llm", env=env)
        sh(*dc, "run", "--rm", "agent", env=env)
        (run_dir / "grants.tsv").write_text(sh(*dc, "exec", "-T", "postgres", *PSQL, env=env, capture=True, check=False))
    finally:
        sh(*dc, "down", "-v", "--remove-orphans", env=env, check=False)


# --------------------------------------------------------------------------- #
# Kubernetes backend: namespace per run, default-deny network policy
# --------------------------------------------------------------------------- #

def make_run_ca(ns: str, run_dir: Path) -> None:
    """Fresh MITM CA per run: a leaked key is only good for one throwaway namespace."""
    key, crt = run_dir / "ca.key", run_dir / "ca.crt"
    sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", f"/CN=faultline {ns}",
       "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
       "-keyout", str(key), "-out", str(crt), capture=True)
    bundle = run_dir / "mitmproxy-ca.pem"  # mitmproxy wants key + cert in one file
    bundle.write_text(key.read_text() + crt.read_text())
    sh("kubectl", "-n", ns, "create", "secret", "generic", "run-ca",
       f"--from-file=mitmproxy-ca.pem={bundle}", f"--from-file=mitmproxy-ca-cert.pem={crt}")
    key.unlink()
    bundle.unlink()


def run_k8s(run_id: str, scenario: str, run_dir: Path) -> None:
    ns = f"faultline-{run_id}"
    manifest = (ROOT / "k8s/run-template/run.yaml").read_text()
    manifest = manifest.replace("__NS__", ns).replace("__SCENARIO__", scenario)
    rendered = run_dir / "run.yaml"
    rendered.write_text(manifest)

    try:
        sh("kubectl", "create", "namespace", ns)
        sh("kubectl", "label", "namespace", ns, "faultline/run=true")
        sh("kubectl", "-n", ns, "create", "configmap", "seed-sql", f"--from-file={ROOT / 'db/seed.sql'}")
        sh("kubectl", "-n", ns, "create", "configmap", "prompts", f"--from-file={ROOT / 'evals/prompts.jsonl'}")
        make_run_ca(ns, run_dir)
        sh("kubectl", "apply", "-f", str(rendered))
        sh("kubectl", "-n", ns, "wait", "--for=condition=complete", "job/agent", "--timeout=300s", check=False)
        # The agent prints one JSON result per line; its pod is gone once the Job ends, logs are not.
        logs = sh("kubectl", "-n", ns, "logs", "job/agent", "-c", "agent", capture=True, check=False)
        (run_dir / "agent_output.jsonl").write_text(
            "".join(l + "\n" for l in logs.splitlines() if l.startswith("{")))
        proxy = sh("kubectl", "-n", ns, "get", "pod", "-l", "app=proxy", "-o", "jsonpath={.items[0].metadata.name}",
                   capture=True)
        sh("kubectl", "-n", ns, "cp", f"{proxy}:/data/tape.jsonl", str(run_dir / "tape.jsonl"), check=False)
        (run_dir / "grants.tsv").write_text(
            sh("kubectl", "-n", ns, "exec", "deploy/postgres", "--", *PSQL, capture=True, check=False))
    finally:
        if not os.environ.get("FAULTLINE_KEEP"):
            sh("kubectl", "delete", "namespace", ns, "--wait=false", check=False)


# --------------------------------------------------------------------------- #

def run_one(scenario: str, backend: str, tag: str = "") -> dict:
    prefix = f"{tag}-" if tag else ""
    run_id = f"{prefix}{scenario.replace('_', '-')}-{time.strftime('%m%d%H%M%S')}-{uuid.uuid4().hex[:4]}"
    run_dir = ROOT / "runs" / run_id
    run_dir.mkdir(parents=True)
    run_dir.chmod(0o777)  # agent container runs as nobody
    backend_fn = run_compose if backend == "compose" else run_k8s
    backend_fn(run_id, scenario, run_dir)
    report = score(run_dir, scenario)
    latest = ROOT / "runs" / f"latest-{prefix}{scenario}"
    if latest.is_symlink() or latest.exists():
        latest.unlink()
    latest.symlink_to(run_dir.name)
    return report


def main() -> None:
    ap = argparse.ArgumentParser(prog="faultline")
    ap.add_argument("--scenario", choices=SCENARIOS, default="baseline")
    ap.add_argument("--all", action="store_true", help="run every scenario")
    ap.add_argument("--backend", choices=["compose", "k8s"], default="compose")
    ap.add_argument("--tag", default="", help="label runs, e.g. the model name (runs/latest-<tag>-<scenario>)")
    ap.add_argument("--env-file", default="", help="compose env file selecting a real model (default: offline mock)")
    ap.add_argument("--trials", type=int, default=1, help="repeat each scenario N times, each in a fresh sandbox")
    args = ap.parse_args()
    global ENV_FILE
    ENV_FILE = args.env_file

    if args.backend == "k8s" and not shutil.which("kubectl"):
        sys.exit("kubectl not found; run scripts/cluster-up.sh first")

    scenarios = SCENARIOS if args.all else [args.scenario]
    by_scenario: dict[str, list[dict]] = {}
    harness_errors: dict[str, int] = {}
    for s in scenarios:
        for i in range(args.trials):
            if args.trials > 1:
                print(f"=== {s} trial {i + 1}/{args.trials}", file=sys.stderr)
            try:
                by_scenario.setdefault(s, []).append(run_one(s, args.backend, args.tag))
            except Exception as e:  # one broken trial shouldn't sink a long batch; it's reported, not scored
                print(f"!!! {s} trial {i + 1} failed: {e}", file=sys.stderr)
                harness_errors[s] = harness_errors.get(s, 0) + 1

    if args.trials == 1:
        print("\n| scenario | passed | findings |")
        print("|---|---|---|")
        for s, (r,) in by_scenario.items():
            kinds = sorted({f["check"] for f in r["findings"]})
            print(f"| {s} | {r['passed']}/{r['cases']} | {', '.join(kinds) or '-'} |")
        for s in harness_errors:
            print(f"| {s} | HARNESS ERROR | not scored |")
        return

    summary = aggregate(by_scenario, harness_errors)
    name = f"summary-{args.tag or 'mock'}-{time.strftime('%m%d%H%M%S')}"
    (ROOT / "runs" / f"{name}.json").write_text(json.dumps(summary, indent=2))
    md = summary_markdown(summary, args.tag or "mock", args.trials)
    (ROOT / "runs" / f"{name}.md").write_text(md)
    print("\n" + md)

if __name__ == "__main__":
    main()
