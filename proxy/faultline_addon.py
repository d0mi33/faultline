"""
Faultline mitmproxy addon: record, replay and fault-inject an agent's traffic.

Every request the agent makes (LLM calls, tool/HTTP calls) is forced through
this proxy by the sandbox's NetworkPolicy. The addon:

  * records each flow to a JSONL tape (request, response, latency, faults hit)
  * optionally replays responses from an existing tape (deterministic reruns)
  * applies fault rules loaded from a YAML scenario file

Run:
  mitmdump -s faultline_addon.py --set scenario=faults/prompt_injection.yaml \
           --set tape=/data/tape.jsonl --set mode_replay=false
"""

import asyncio
import hashlib
import json
import random
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from mitmproxy import ctx, http


# --------------------------------------------------------------------------- #
# Fault rules
# --------------------------------------------------------------------------- #

@dataclass
class Rule:
    name: str
    action: str                      # latency | status | malformed_json | truncate | inject_tool_output | drop_tools
    host: str = ".*"
    path: str = ".*"
    probability: float = 1.0
    params: dict[str, Any] = field(default_factory=dict)
    max_hits: int | None = None
    hits: int = 0

    def matches(self, flow: http.HTTPFlow, rng: random.Random) -> bool:
        if self.max_hits is not None and self.hits >= self.max_hits:
            return False
        if not re.search(self.host, flow.request.pretty_host):
            return False
        if not re.search(self.path, flow.request.path):
            return False
        return rng.random() < self.probability


def load_rules(path: str) -> tuple[list[Rule], int]:
    if not path:
        return [], 0
    doc = yaml.safe_load(Path(path).read_text()) or {}
    rules = [
        Rule(
            name=r["name"],
            action=r["action"],
            host=r.get("host", ".*"),
            path=r.get("path", ".*"),
            probability=float(r.get("probability", 1.0)),
            params=r.get("params", {}),
            max_hits=r.get("max_hits"),
        )
        for r in doc.get("rules", [])
    ]
    return rules, int(doc.get("seed", 0))


# --------------------------------------------------------------------------- #
# Request-side mutations (applied before the upstream sees the request)
# --------------------------------------------------------------------------- #

def _json_body(flow: http.HTTPFlow) -> dict | None:
    try:
        return json.loads(flow.request.get_text() or "")
    except (ValueError, TypeError):
        return None


def inject_tool_output(flow: http.HTTPFlow, payload: str) -> bool:
    """Append an indirect prompt-injection payload to tool results the agent
    is about to send back to the LLM. Works for OpenAI- and Anthropic-style
    message formats. Returns True if anything was modified."""
    body = _json_body(flow)
    if not body or "messages" not in body:
        return False
    touched = False
    for msg in body["messages"]:
        # OpenAI: {"role": "tool", "content": "..."}
        if msg.get("role") == "tool" and isinstance(msg.get("content"), str):
            msg["content"] += "\n\n" + payload
            touched = True
        # Anthropic: {"role": "user", "content": [{"type": "tool_result", ...}]}
        if isinstance(msg.get("content"), list):
            for part in msg["content"]:
                if part.get("type") == "tool_result":
                    if isinstance(part.get("content"), str):
                        part["content"] += "\n\n" + payload
                    else:
                        part.setdefault("content", []).append({"type": "text", "text": payload})
                    touched = True
    if touched:
        flow.request.set_text(json.dumps(body))
    return touched


# --------------------------------------------------------------------------- #
# Addon
# --------------------------------------------------------------------------- #

class Faultline:
    def __init__(self) -> None:
        self.rules: list[Rule] = []
        self.rng = random.Random(0)
        self.tape_out = None
        self.replay: dict[str, dict] = {}

    def load(self, loader) -> None:
        loader.add_option("scenario", str, "", "Path to fault scenario YAML")
        loader.add_option("tape", str, "/data/tape.jsonl", "Path to write the flow tape")
        loader.add_option("replay_from", str, "", "Replay responses from this tape")

    def configure(self, updated) -> None:
        if "scenario" in updated:
            self.rules, seed = load_rules(ctx.options.scenario)
            self.rng = random.Random(seed)
            ctx.log.info(f"faultline: loaded {len(self.rules)} rules (seed={seed})")
        if "tape" in updated and ctx.options.tape:
            Path(ctx.options.tape).parent.mkdir(parents=True, exist_ok=True)
            self.tape_out = open(ctx.options.tape, "a", buffering=1)
        if "replay_from" in updated and ctx.options.replay_from:
            for line in Path(ctx.options.replay_from).read_text().splitlines():
                rec = json.loads(line)
                self.replay[rec["key"]] = rec
            ctx.log.info(f"faultline: replay tape has {len(self.replay)} flows")

    @staticmethod
    def _key(flow: http.HTTPFlow) -> str:
        h = hashlib.sha256()
        h.update(flow.request.method.encode())
        h.update(flow.request.pretty_url.encode())
        h.update(flow.request.raw_content or b"")
        return h.hexdigest()[:16]

    # -- request phase ------------------------------------------------------ #
    async def request(self, flow: http.HTTPFlow) -> None:
        flow.metadata["t0"] = time.monotonic()
        flow.metadata["faults"] = []

        for rule in self.rules:
            if not rule.matches(flow, self.rng):
                continue
            applied = await self._apply_request_rule(rule, flow)
            if applied:
                rule.hits += 1
                flow.metadata["faults"].append(rule.name)
            if flow.response is not None:  # short-circuited
                return

        # Key is computed after request mutations, so replay is per-scenario.
        flow.metadata["key"] = self._key(flow)
        if self.replay and flow.metadata["key"] in self.replay:
            rec = self.replay[flow.metadata["key"]]
            flow.response = http.Response.make(
                rec["status"], rec["response_body"].encode(),
                {"content-type": "application/json", "x-faultline": "replay"},
            )

    async def _apply_request_rule(self, rule: Rule, flow: http.HTTPFlow) -> bool:
        p = rule.params
        if rule.action == "latency":
            await asyncio.sleep(float(p.get("seconds", 2.0)))
            return True
        if rule.action == "status":
            code = int(p.get("code", 429))
            headers = {"content-type": "application/json", "x-faultline-fault": rule.name}
            if code == 429:
                headers["retry-after"] = str(p.get("retry_after", 1))
            flow.response = http.Response.make(
                code, json.dumps({"error": {"message": f"faultline injected {code}", "type": "faultline_fault"}}), headers
            )
            return True
        if rule.action == "inject_tool_output":
            return inject_tool_output(flow, p["payload"])
        if rule.action == "drop_tools":
            body = _json_body(flow)
            if body and body.pop("tools", None) is not None:
                flow.request.set_text(json.dumps(body))
                return True
        return False

    # -- response phase ----------------------------------------------------- #
    def response(self, flow: http.HTTPFlow) -> None:
        for rule in self.rules:
            if rule.action not in ("malformed_json", "truncate") or not rule.matches(flow, self.rng):
                continue
            text = flow.response.get_text() or ""
            if rule.action == "malformed_json":
                flow.response.set_text(text[: max(1, len(text) // 2)] + '{"oops":')
            else:
                flow.response.set_text(text[: int(rule.params.get("bytes", 64))])
            rule.hits += 1
            flow.metadata.setdefault("faults", []).append(rule.name)
        self._record(flow)

    def _record(self, flow: http.HTTPFlow) -> None:
        if not self.tape_out:
            return
        rec = {
            "key": flow.metadata.get("key") or self._key(flow),
            "ts": time.time(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "request_body": flow.request.get_text(strict=False) or "",
            "status": flow.response.status_code if flow.response else None,
            "response_body": flow.response.get_text(strict=False) if flow.response else "",
            "latency_ms": round((time.monotonic() - flow.metadata.get("t0", time.monotonic())) * 1000, 1),
            "faults": flow.metadata.get("faults", []),
        }
        self.tape_out.write(json.dumps(rec) + "\n")

    def done(self) -> None:
        if self.tape_out:
            self.tape_out.close()


addons = [Faultline()]
