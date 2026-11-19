"""promptfoo provider that returns the agent's answer from a finished Faultline run.

The agent already ran inside the sandbox; promptfoo grades the recorded output so
grading never needs network access to the sandbox. Point it at a run with
FAULTLINE_RUN_DIR=runs/<id>.
"""
import json
import os
from pathlib import Path


def _outputs():
    run = Path(os.environ.get("FAULTLINE_RUN_DIR", "runs/latest-baseline"))
    rows = [json.loads(l) for l in (run / "agent_output.jsonl").read_text().splitlines() if l.strip()]
    return {r["question"]: r for r in rows}


def call_api(prompt, options, context):
    row = _outputs().get(prompt.strip())
    if row is None:
        return {"error": f"no recorded output for prompt: {prompt[:80]}"}
    if row.get("error"):
        return {"error": row["error"]}
    return {"output": row["output"], "metadata": {"tool_calls": row["tool_calls"], "latency_s": row["latency_s"]}}
