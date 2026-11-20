"""
faultline.map: the agent's attack surface, from what a run actually did.

  python -m faultline.map runs/latest-baseline

No model calls. It reads three things a run already produced:
  * tape.jsonl   the tools the agent offered the model, which ones the model
                 called, and every host the proxy forwarded to
  * grants.tsv   per-column SELECT privilege of the agent's DB role
  * policy.yaml  what the agent is supposed to reach

and writes surface.json + surface.md (with a mermaid graph) into the run dir.
Findings are mismatches between the policy and what's really reachable.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

from faultline.score import load_jsonl

ROOT = Path(__file__).resolve().parent.parent


def _json(s: str) -> dict:
    try:
        return json.loads(s or "")
    except ValueError:
        return {}


def tools_from_tape(tape: list[dict]) -> tuple[dict[str, dict], dict[str, int]]:
    """Tool schemas offered to the model, and how often the model called each."""
    offered: dict[str, dict] = {}
    called: dict[str, int] = {}
    for flow in tape:
        for t in _json(flow.get("request_body", "")).get("tools") or []:
            fn = t.get("function", t)  # OpenAI nests under "function"; Anthropic doesn't
            offered.setdefault(fn["name"], {"description": fn.get("description", ""),
                                            "parameters": sorted((fn.get("parameters") or fn.get("input_schema") or {})
                                                                 .get("properties", {}))})
        for choice in _json(flow.get("response_body", "")).get("choices") or []:
            for tc in (choice.get("message") or {}).get("tool_calls") or []:
                name = tc["function"]["name"]
                called[name] = called.get(name, 0) + 1
    return offered, called


def load_grants(path: Path) -> dict[str, bool]:
    grants = {}
    if path.exists():
        for line in path.read_text().splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                grants[f"{parts[0]}.{parts[1]}"] = parts[2] == "t"
    return grants


def build(run_dir: Path, policy: dict) -> dict:
    tape = load_jsonl(run_dir / "tape.jsonl")
    if not tape:
        raise RuntimeError(f"no tape in {run_dir}; run a scenario first")
    offered, called = tools_from_tape(tape)
    grants = load_grants(run_dir / "grants.tsv")
    hosts = sorted({re.sub(r"^https?://([^/]+).*", r"\1", f["url"]) for f in tape})
    bindings = policy.get("tools", {})
    sensitive = set(policy.get("sensitive_columns", []))
    allowed = [re.compile(p) for p in policy.get("allowed_egress", [])]

    findings = []

    def find(severity, check, detail):
        findings.append({"severity": severity, "check": check, "detail": detail})

    for name in offered:
        if name not in bindings:
            find("medium", "unbound_tool", f"`{name}` is offered to the model but policy.yaml doesn't say what it reaches")
    for name in bindings:
        if name not in offered:
            find("info", "tool_not_offered", f"`{name}` is in policy.yaml but the agent never offered it")
    if any(b.get("resource") == "database" for b in bindings.values()):
        if not grants:
            find("medium", "grants_unknown", "no grants.tsv in this run, so database reach can't be checked")
        for col in sorted(sensitive):
            if grants.get(col):
                find("high", "sensitive_column_readable", f"agent role can SELECT `{col}`")
            elif col not in grants:
                find("info", "sensitive_column_missing", f"`{col}` is in policy.yaml but not in the database")
    for h in hosts:
        if not any(p.search(h) for p in allowed):
            find("high", "unexpected_egress", f"proxy forwarded traffic to `{h}`")

    return {
        "run": run_dir.name,
        "tools": {n: {**t, "calls": called.get(n, 0), "resource": bindings.get(n, {}).get("resource")}
                  for n, t in offered.items()},
        "columns": {c: {"readable": r, "sensitive": c in sensitive} for c, r in grants.items()},
        "egress_hosts": hosts,
        "findings": sorted(findings, key=lambda f: ["high", "medium", "info"].index(f["severity"])),
    }


def _id(s: str) -> str:
    return re.sub(r"\W", "_", s)


def mermaid(s: dict) -> str:
    lines = ["flowchart LR", '  user(["customer message"]) --> agent["agent"]']
    for name, t in s["tools"].items():
        lines.append(f'  agent -->|"{t["calls"]} calls"| T_{_id(name)}["tool: {name}"]')
        if t["resource"] == "database":
            tables = sorted({c.split(".")[0] for c in s["columns"]})
            for tbl in tables:
                cols = {c: v for c, v in s["columns"].items() if c.startswith(tbl + ".")}
                ok = [c.split(".")[1] for c, v in cols.items() if v["readable"]]
                denied = [c.split(".")[1] for c, v in cols.items() if not v["readable"]]
                lines.append(f'  T_{_id(name)} --> D_{_id(tbl)}[("{tbl}: {", ".join(ok) or "nothing"}")]')
                if denied:
                    lines.append(f'  T_{_id(name)} -.-x X_{_id(tbl)}["{tbl}: {", ".join(denied)} (denied)"]')
    for h in s["egress_hosts"]:
        lines.append(f'  agent -->|"via proxy"| H_{_id(h)}{{{{"{h}"}}}}')
    return "\n".join(lines)


def to_markdown(s: dict) -> str:
    out = [f"# Attack surface: `{s['run']}`", "", "```mermaid", mermaid(s), "```", "", "## Tools offered to the model", "",
           "| tool | parameters | bound to | calls in this run |", "|---|---|---|---|"]
    out += [f"| {n} | {', '.join(t['parameters']) or '-'} | {t['resource'] or '**unbound**'} | {t['calls']} |"
            for n, t in s["tools"].items()]
    out += ["", "## Database reach (agent role)", "", "| column | readable | sensitive |", "|---|---|---|"]
    out += [f"| {c} | {'yes' if v['readable'] else 'no'} | {'yes' if v['sensitive'] else ''} |"
            for c, v in s["columns"].items()]
    out += ["", f"## Egress\n\n{', '.join(f'`{h}`' for h in s['egress_hosts'])}", "", "## Findings", ""]
    out += [f"- **{f['severity']}** `{f['check']}`: {f['detail']}" for f in s["findings"]] or ["None: the run matches policy.yaml."]
    return "\n".join(out) + "\n"


def main() -> None:
    run_dir = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "runs/latest-baseline").resolve()
    policy = yaml.safe_load(Path(sys.argv[2] if len(sys.argv) > 2 else ROOT / "policy.yaml").read_text())
    surface = build(run_dir, policy)
    (run_dir / "surface.json").write_text(json.dumps(surface, indent=2))
    (run_dir / "surface.md").write_text(to_markdown(surface))
    print(to_markdown(surface))
    sys.exit(1 if any(f["severity"] == "high" for f in surface["findings"]) else 0)


if __name__ == "__main__":
    main()
